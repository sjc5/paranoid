use super::*;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::email_otp_method::{
    EmailOtpCompleteChallengeResponse, EmailOtpIssueChallenge, EmailOtpResendChallenge,
    PostgresEmailOtpMethodPlugin, PostgresEmailOtpMethodPluginConfig,
    PostgresEmailOtpSubjectResolver, PostgresEmailOtpVerifiedIdentifier,
};
use super::super::postgres_method_runtime::PostgresAuthMethodPlugin;
use super::super::postgres_password_derived_signature_method::{
    PasswordDerivedSignatureVerifierForTest, PostgresPasswordDerivedSignatureMethodPlugin,
    PostgresPasswordDerivedSignatureMethodPluginConfig,
};
use super::super::postgres_recovery_code_method::{
    PostgresRecoveryCodeMethodPlugin, PostgresRecoveryCodeMethodPluginConfig,
};
use super::super::postgres_totp_method::{
    PostgresTotpCodeVerifier, PostgresTotpMethodError, PostgresTotpMethodPlugin,
    PostgresTotpMethodPluginConfig,
};
use crate::crypto::{
    PASSWORD_KDF_MIN_ITERATIONS, PASSWORD_KDF_MIN_MEMORY_COST_KIB, PASSWORD_KDF_SALT_SIZE,
    PasswordKdfParams, PasswordKdfSalt, SecretBytes,
};
use crate::db::{
    BootstrapConfig, DatabaseOperationObserver, PgIdentifier, PgQualifiedTableName, PgSchemaName,
    Pool, PoolConfig, Tx, WritePool, pooler_safe_query, pooler_safe_query_as,
    pooler_safe_query_scalar, unparameterized_simple_query,
};
use http::HeaderMap;
use http::header::{COOKIE, HeaderValue};
use secrecy::SecretString;

static AUTH_POSTGRES_RUNTIME_TEST_COUNTER: AtomicU64 = AtomicU64::new(1);
static AUTH_POSTGRES_RUNTIME_TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

macro_rules! auth_runtime_test_fetch_one_in_transaction {
    ($pool:expr, $query:expr, $expect_message:literal) => {{
        let mut tx = $pool
            .begin_transaction()
            .await
            .expect("begin auth runtime test read transaction");
        let value = $query
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .expect($expect_message);
        tx.rollback()
            .await
            .expect("rollback auth runtime test read transaction");
        value
    }};
}

macro_rules! auth_runtime_test_fetch_optional_in_transaction {
    ($pool:expr, $query:expr, $expect_message:literal) => {{
        let mut tx = $pool
            .begin_transaction()
            .await
            .expect("begin auth runtime test read transaction");
        let value = $query
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .expect($expect_message);
        tx.rollback()
            .await
            .expect("rollback auth runtime test read transaction");
        value
    }};
}

struct PostgresRuntimeTestHarness {
    pool: Pool,
    database_operation_observer: DatabaseOperationObserver,
    store_config: super::super::postgres_store::PostgresAuthStoreConfig,
    runtime: super::super::postgres_runtime::PostgresAuthWebRuntime,
    schema: PgSchemaName,
    method_plugin: Option<Arc<TestPostgresAuthMethodPlugin>>,
    email_otp_plugin: Option<Arc<PostgresEmailOtpMethodPlugin>>,
    totp_plugin: Option<Arc<PostgresTotpMethodPlugin<TestTotpCodeVerifier>>>,
    recovery_code_plugin: Option<Arc<PostgresRecoveryCodeMethodPlugin>>,
    password_derived_signature_plugin: Option<Arc<PostgresPasswordDerivedSignatureMethodPlugin>>,
}

#[derive(Clone, Copy, Default)]
struct FirstPartyMethodSelection {
    include_totp_plugin: bool,
    include_recovery_code_plugin: bool,
    include_password_derived_signature_plugin: bool,
}

impl PostgresRuntimeTestHarness {
    async fn connect_required() -> Self {
        Self::connect_required_with_registered_plugins(None, true).await
    }

    async fn connect_required_without_method_registry() -> Self {
        Self::connect_required_with_registered_plugins(None, false).await
    }

    async fn connect_required_with_method_plugin(
        failure_mode: Option<TestMethodCommitFailureMode>,
    ) -> Self {
        Self::connect_required_with_registered_plugins(failure_mode, false).await
    }

    async fn connect_required_with_email_otp_method() -> Self {
        Self::connect_required_with_registered_plugins(None, true).await
    }

    async fn connect_required_with_email_otp_subject_resolver(
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method_and_configured_methods(
            None,
            true,
            Some(subject_resolver),
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection::default(),
        )
        .await
    }

    async fn connect_required_with_message_signature_method() -> Self {
        Self::connect_required_with_registered_test_method(
            ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
                .expect("message signature method"),
        )
        .await
    }

    async fn connect_required_with_origin_bound_public_key_method() -> Self {
        Self::connect_required_with_registered_test_method(
            ProofMethodDeclaration::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
                .expect("origin-bound public-key method"),
        )
        .await
    }

    async fn connect_required_with_federated_identity_method() -> Self {
        Self::connect_required_with_registered_test_method(
            ProofMethodDeclaration::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
                .expect("federated identity method"),
        )
        .await
    }

    async fn connect_required_with_totp_method() -> Self {
        Self::connect_required_with_configured_secret_plugins(true, false).await
    }

    async fn connect_required_with_recovery_code_method() -> Self {
        Self::connect_required_with_configured_secret_plugins(false, true).await
    }

    async fn connect_required_with_password_derived_signature_method() -> Self {
        Self::connect_required_with_registered_plugins_for_test_method_and_configured_methods(
            None,
            true,
            None,
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection {
                include_password_derived_signature_plugin: true,
                ..FirstPartyMethodSelection::default()
            },
        )
        .await
    }

    async fn connect_required_with_configured_secret_plugins(
        include_totp_plugin: bool,
        include_recovery_code_plugin: bool,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method_and_configured_methods(
            None,
            true,
            None,
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection {
                include_totp_plugin,
                include_recovery_code_plugin,
                ..FirstPartyMethodSelection::default()
            },
        )
        .await
    }

    async fn connect_required_with_registered_test_method(method: ProofMethodDeclaration) -> Self {
        Self::connect_required_with_registered_test_method_and_verification_mode(
            method,
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await
    }

    async fn connect_required_with_registered_authoritative_test_method(
        method: ProofMethodDeclaration,
    ) -> Self {
        Self::connect_required_with_registered_test_method_and_verification_mode(
            method,
            TestActiveMethodVerificationMode::AuthoritativeConfirmation,
        )
        .await
    }

    async fn connect_required_with_registered_test_method_and_verification_mode(
        method: ProofMethodDeclaration,
        active_method_verification_mode: TestActiveMethodVerificationMode,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
            None,
            Some(method),
            active_method_verification_mode,
        )
        .await
    }

    async fn connect_required_with_registered_plugins(
        failure_mode: Option<TestMethodCommitFailureMode>,
        include_email_otp_plugin: bool,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method(
            failure_mode,
            include_email_otp_plugin,
            None,
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await
    }

    async fn connect_required_with_registered_plugins_for_test_method(
        failure_mode: Option<TestMethodCommitFailureMode>,
        include_email_otp_plugin: bool,
        email_otp_subject_resolver: Option<Arc<dyn PostgresEmailOtpSubjectResolver>>,
        test_method: Option<ProofMethodDeclaration>,
        active_method_verification_mode: TestActiveMethodVerificationMode,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method_and_configured_methods(
            failure_mode,
            include_email_otp_plugin,
            email_otp_subject_resolver,
            test_method,
            active_method_verification_mode,
            FirstPartyMethodSelection::default(),
        )
        .await
    }

    async fn connect_required_with_registered_plugins_for_test_method_and_configured_methods(
        failure_mode: Option<TestMethodCommitFailureMode>,
        include_email_otp_plugin: bool,
        email_otp_subject_resolver: Option<Arc<dyn PostgresEmailOtpSubjectResolver>>,
        test_method: Option<ProofMethodDeclaration>,
        active_method_verification_mode: TestActiveMethodVerificationMode,
        first_party_methods: FirstPartyMethodSelection,
    ) -> Self {
        let database_url = required_auth_postgres_runtime_test_database_url();

        let write_pool =
            WritePool::connect(PoolConfig::new(SecretString::from(database_url.clone())))
                .await
                .expect("connect write test database");
        let raw_pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
            .await
            .expect("connect test database");
        let database_operation_observer = DatabaseOperationObserver::default();
        let pool =
            raw_pool.clone_with_database_operation_observer(database_operation_observer.clone());
        let schema_name = unique_runtime_test_schema_name();
        let schema = PgSchemaName::new(schema_name.clone());
        let create_schema = format!("CREATE SCHEMA {}", schema_name.quoted());
        unparameterized_simple_query(sqlx::AssertSqlSafe(create_schema.as_str()))
            .execute(raw_pool.sqlx_pool())
            .await
            .expect("create auth runtime test schema");

        let store_config = super::super::postgres_store::PostgresAuthStoreConfig::new(
            Some(schema.clone()),
            PgIdentifier::new("__paranoid_auth_").expect("table prefix"),
        )
        .expect("store config");
        let method_plugin = match (failure_mode, test_method) {
            (Some(failure_mode), Some(method)) => Some(Arc::new(
                TestPostgresAuthMethodPlugin::with_method_and_verification_mode(
                    &schema,
                    method,
                    failure_mode,
                    active_method_verification_mode,
                ),
            )),
            (Some(failure_mode), None) => Some(Arc::new(TestPostgresAuthMethodPlugin::new(
                &schema,
                failure_mode,
            ))),
            (None, Some(method)) => Some(Arc::new(
                TestPostgresAuthMethodPlugin::with_method_and_verification_mode(
                    &schema,
                    method,
                    TestMethodCommitFailureMode::None,
                    active_method_verification_mode,
                ),
            )),
            (None, None) => None,
        };
        let email_otp_plugin = if include_email_otp_plugin {
            let mut plugin = PostgresEmailOtpMethodPlugin::new(
                PostgresEmailOtpMethodPluginConfig::new(
                    Some(schema.clone()),
                    PgIdentifier::new("__paranoid_auth_email_otp_")
                        .expect("email otp table prefix"),
                )
                .expect("email otp method config"),
                test_keyset("tests.auth.postgres-runtime.email-otp.v1"),
            )
            .expect("email otp method plugin");
            let subject_resolver = email_otp_subject_resolver
                .unwrap_or_else(|| Arc::new(EmbeddedSubjectEmailOtpResolver));
            plugin = plugin.with_subject_resolver(subject_resolver);
            Some(Arc::new(plugin))
        } else {
            None
        };
        let totp_plugin = if first_party_methods.include_totp_plugin {
            Some(Arc::new(
                PostgresTotpMethodPlugin::new(
                    PostgresTotpMethodPluginConfig::new(
                        Some(schema.clone()),
                        PgIdentifier::new("__paranoid_auth_totp_").expect("totp table prefix"),
                    )
                    .expect("totp method config"),
                    test_keyset("tests.auth.postgres-runtime.totp.v1"),
                    TestTotpCodeVerifier,
                )
                .expect("totp method plugin"),
            ))
        } else {
            None
        };
        let recovery_code_plugin = if first_party_methods.include_recovery_code_plugin {
            Some(Arc::new(
                PostgresRecoveryCodeMethodPlugin::new(
                    PostgresRecoveryCodeMethodPluginConfig::new(
                        Some(schema.clone()),
                        PgIdentifier::new("__paranoid_auth_recovery_code_")
                            .expect("recovery code table prefix"),
                    )
                    .expect("recovery code method config"),
                    test_keyset("tests.auth.postgres-runtime.recovery-code.v1"),
                )
                .expect("recovery code method plugin"),
            ))
        } else {
            None
        };
        let password_derived_signature_plugin =
            if first_party_methods.include_password_derived_signature_plugin {
                Some(Arc::new(
                    PostgresPasswordDerivedSignatureMethodPlugin::new(
                        PostgresPasswordDerivedSignatureMethodPluginConfig::new(
                            Some(schema.clone()),
                            PgIdentifier::new("__paranoid_auth_password_signature_")
                                .expect("password-derived signature table prefix"),
                        )
                        .expect("password-derived signature method config"),
                    )
                    .expect("password-derived signature method plugin"),
                ))
            } else {
                None
            };
        let mut store = super::super::postgres_store::PostgresAuthStore::new(
            store_config.clone(),
            test_keyset("tests.auth.postgres-runtime.credentials.v1"),
        );
        let mut plugins: Vec<
            Arc<dyn super::super::postgres_method_runtime::PostgresAuthMethodPlugin>,
        > = Vec::new();
        if let Some(plugin) = method_plugin.as_ref() {
            plugins.push(plugin.clone());
        }
        if let Some(plugin) = email_otp_plugin.as_ref() {
            plugins.push(plugin.clone());
        }
        if let Some(plugin) = totp_plugin.as_ref() {
            plugins.push(plugin.clone());
        }
        if let Some(plugin) = recovery_code_plugin.as_ref() {
            plugins.push(plugin.clone());
        }
        if let Some(plugin) = password_derived_signature_plugin.as_ref() {
            plugins.push(plugin.clone());
        }
        if !plugins.is_empty() {
            let registry =
                super::super::postgres_method_runtime::PostgresAuthMethodRegistry::new(plugins)
                    .expect("test method registry");
            store = store.with_method_registry(Arc::new(registry));
        }
        store
            .migrate_schema(&write_pool)
            .await
            .expect("migrate auth schema");
        let runtime = super::super::postgres_runtime::PostgresAuthWebRuntime::new(
            AuthWebRuntime::new(config(), auth_web_transport()),
            pool.clone(),
            store,
            Arc::new(hashcash_verifier_for_test()),
        );

        Self {
            pool,
            database_operation_observer,
            store_config,
            runtime,
            schema,
            method_plugin,
            email_otp_plugin,
            totp_plugin,
            recovery_code_plugin,
            password_derived_signature_plugin,
        }
    }

    async fn drop_schema(&self) {
        let drop_schema = format!("DROP SCHEMA {} CASCADE", self.schema.identifier().quoted());
        unparameterized_simple_query(sqlx::AssertSqlSafe(drop_schema.as_str()))
            .execute(self.pool.sqlx_pool())
            .await
            .expect("drop auth runtime test schema");
    }
}

fn assert_no_database_operations(observer: &DatabaseOperationObserver, expectation: &'static str) {
    let records = observer.records();
    assert!(
        records.is_empty(),
        "{expectation}; observed database operations: {records:?}"
    );
}

fn assert_database_operations_include_label(
    observer: &DatabaseOperationObserver,
    expected_label: &'static str,
    expectation: &'static str,
) {
    let records = observer.records();
    assert!(
        records.iter().any(|record| record.label == expected_label),
        "{expectation}; expected database operation label {expected_label:?}; observed database operations: {records:?}"
    );
}

fn email_otp_plugin_for_harness(
    harness: &PostgresRuntimeTestHarness,
) -> &PostgresEmailOtpMethodPlugin {
    harness
        .email_otp_plugin
        .as_ref()
        .expect("email otp method plugin")
}

fn password_derived_signature_plugin_for_harness(
    harness: &PostgresRuntimeTestHarness,
) -> &PostgresPasswordDerivedSignatureMethodPlugin {
    harness
        .password_derived_signature_plugin
        .as_ref()
        .expect("password-derived signature method plugin")
}

struct EmbeddedSubjectEmailOtpResolver;

impl PostgresEmailOtpSubjectResolver for EmbeddedSubjectEmailOtpResolver {
    fn resolve_verified_identifier_for_recipient_handle<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        recipient_handle: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PostgresEmailOtpVerifiedIdentifier,
                        super::super::email_otp_method::PostgresEmailOtpMethodError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let Some(subject_label) = recipient_handle
                .rsplit_once(":subject:")
                .map(|(_, label)| label)
            else {
                return Ok(PostgresEmailOtpVerifiedIdentifier::new(
                    None,
                    id("embedded-email-otp-unresolved-source"),
                ));
            };
            let subject_id = SubjectId::from_bytes(subject_label.as_bytes().to_vec())
                .map_err(super::super::email_otp_method::PostgresEmailOtpMethodError::Core)?;
            Ok(PostgresEmailOtpVerifiedIdentifier::new(
                Some(subject_id),
                id(&format!("embedded-email-source:{subject_label}")),
            ))
        })
    }
}

struct StaticEmailOtpSubjectResolver {
    recipient_handle: String,
    subject_id: SubjectId,
    source_id: VerifiedProofSourceId,
    calls: AtomicU64,
}

impl StaticEmailOtpSubjectResolver {
    fn new(
        recipient_handle: &str,
        subject_id: SubjectId,
        source_id: VerifiedProofSourceId,
    ) -> Self {
        Self {
            recipient_handle: recipient_handle.to_owned(),
            subject_id,
            source_id,
            calls: AtomicU64::new(0),
        }
    }

    fn call_count(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl PostgresEmailOtpSubjectResolver for StaticEmailOtpSubjectResolver {
    fn resolve_verified_identifier_for_recipient_handle<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        recipient_handle: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PostgresEmailOtpVerifiedIdentifier,
                        super::super::email_otp_method::PostgresEmailOtpMethodError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if recipient_handle == self.recipient_handle {
                Ok(PostgresEmailOtpVerifiedIdentifier::new(
                    Some(self.subject_id.clone()),
                    self.source_id.clone(),
                ))
            } else {
                Ok(PostgresEmailOtpVerifiedIdentifier::new(
                    None,
                    id("static-email-otp-unresolved-source"),
                ))
            }
        })
    }
}

#[derive(Clone, Copy)]
enum TestMethodCommitFailureMode {
    None,
    FailMutation,
    FailDurableEffectCommand,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TestActiveMethodVerificationMode {
    BeforeStateLoad,
    AuthoritativeConfirmation,
}

struct TestPostgresAuthMethodPlugin {
    method: ProofMethodDeclaration,
    state_table: PgQualifiedTableName,
    durable_effect_table: PgQualifiedTableName,
    failure_mode: TestMethodCommitFailureMode,
    active_method_verification_mode: TestActiveMethodVerificationMode,
}

#[derive(Clone, Copy)]
struct TestTotpCodeVerifier;

impl PostgresTotpCodeVerifier for TestTotpCodeVerifier {
    fn verify_totp_code(
        &self,
        secret: &SecretBytes,
        submitted_code: &[u8],
        now: UnixSeconds,
    ) -> Result<bool, PostgresTotpMethodError> {
        Ok(submitted_code == test_totp_code_bytes(secret.expose_secret(), now))
    }

    fn accepted_totp_codes_for_challenge_window(
        &self,
        secret: &SecretBytes,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Vec<KnownSubjectActiveProofSecretResponse>, PostgresTotpMethodError> {
        if expires_at <= issued_at {
            return Err(PostgresTotpMethodError::Core(
                Error::ActiveProofChallengeCookieExpiresAtOrBeforeIssuedAt,
            ));
        }
        let first_step = issued_at.get() / 30;
        let last_step = expires_at
            .get()
            .checked_sub(1)
            .ok_or(PostgresTotpMethodError::Core(Error::TimeOverflow))?
            / 30;
        let mut accepted_codes = Vec::new();
        for step in first_step..=last_step {
            let step_time = step
                .checked_mul(30)
                .ok_or(PostgresTotpMethodError::Core(Error::TimeOverflow))?;
            accepted_codes.push(
                KnownSubjectActiveProofSecretResponse::try_from_bytes(test_totp_code_bytes(
                    secret.expose_secret(),
                    UnixSeconds::new(step_time),
                ))
                .map_err(PostgresTotpMethodError::Core)?,
            );
        }
        Ok(accepted_codes)
    }
}

impl TestPostgresAuthMethodPlugin {
    fn new(schema: &PgSchemaName, failure_mode: TestMethodCommitFailureMode) -> Self {
        Self {
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("test method declaration"),
            state_table: PgQualifiedTableName::new(
                Some(schema.clone()),
                PgIdentifier::new("__paranoid_auth_test_method_state").expect("state table name"),
            ),
            durable_effect_table: PgQualifiedTableName::new(
                Some(schema.clone()),
                PgIdentifier::new("__paranoid_auth_test_method_durable_effects")
                    .expect("durable effect table name"),
            ),
            failure_mode,
            active_method_verification_mode: TestActiveMethodVerificationMode::BeforeStateLoad,
        }
    }

    fn with_method(
        schema: &PgSchemaName,
        method: ProofMethodDeclaration,
        failure_mode: TestMethodCommitFailureMode,
    ) -> Self {
        let mut plugin = Self::new(schema, failure_mode);
        plugin.method = method;
        plugin
    }

    fn with_method_and_verification_mode(
        schema: &PgSchemaName,
        method: ProofMethodDeclaration,
        failure_mode: TestMethodCommitFailureMode,
        active_method_verification_mode: TestActiveMethodVerificationMode,
    ) -> Self {
        let mut plugin = Self::with_method(schema, method, failure_mode);
        plugin.active_method_verification_mode = active_method_verification_mode;
        plugin
    }

    async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), super::super::postgres_store::PostgresAuthMethodCommitError> {
        let state_statement = format!(
            r#"
            CREATE TABLE {} (
                payload BYTEA PRIMARY KEY,
                proof_family INTEGER NOT NULL,
                method_label TEXT COLLATE "C" NOT NULL,
                mutation_operation TEXT COLLATE "C" NOT NULL
            )
            "#,
            self.state_table.quoted()
        );
        tx.record_database_operation(
            crate::db::DatabaseOperationKind::Execute,
            "auth_core.test_method.schema.create_state_table",
            Some(state_statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(state_statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(crate::db::DbError::query)?;
        let durable_effect_statement = format!(
            r#"
            CREATE TABLE {} (
                method_effect_id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                payload BYTEA NOT NULL,
                proof_family INTEGER NOT NULL,
                method_label TEXT COLLATE "C" NOT NULL,
                durable_effect_operation TEXT COLLATE "C" NOT NULL
            )
            "#,
            self.durable_effect_table.quoted()
        );
        tx.record_database_operation(
            crate::db::DatabaseOperationKind::Execute,
            "auth_core.test_method.schema.create_durable_effect_table",
            Some(durable_effect_statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(durable_effect_statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(crate::db::DbError::query)?;
        Ok(())
    }

    async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), super::super::postgres_store::PostgresAuthMethodCommitError> {
        validate_test_method_table_exists(tx, &self.state_table).await?;
        validate_test_method_table_exists(tx, &self.durable_effect_table).await
    }

    async fn count_state_rows(&self, pool: &Pool) -> i64 {
        let statement = format!("SELECT count(*) FROM {}", self.state_table.quoted());
        auth_runtime_test_fetch_one_in_transaction!(
            pool,
            pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
            "count test method state rows"
        )
    }

    async fn count_durable_effect_rows(&self, pool: &Pool) -> i64 {
        let statement = format!(
            "SELECT count(*) FROM {}",
            self.durable_effect_table.quoted()
        );
        auth_runtime_test_fetch_one_in_transaction!(
            pool,
            pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
            "count test method durable effect rows"
        )
    }

    fn validate_operation(
        actual: &str,
        expected: &'static str,
    ) -> Result<(), super::super::postgres_store::PostgresAuthMethodCommitError> {
        if actual == expected {
            Ok(())
        } else {
            Err(
                super::super::postgres_store::PostgresAuthMethodCommitError::InvalidOperation(
                    actual.to_owned(),
                ),
            )
        }
    }

    fn challenge_presentation_prefix(
        &self,
    ) -> Result<&'static [u8], super::super::postgres_method_runtime::PostgresAuthMethodBuildError>
    {
        test_challenge_presentation_prefix(self.method.family()).ok_or_else(|| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_method_challenge_issue",
                "test plugin cannot issue this proof family".to_owned(),
            )
        })
    }

    fn response_challenge_prefix(
        &self,
    ) -> Result<&'static [u8], super::super::postgres_method_runtime::PostgresAuthMethodBuildError>
    {
        test_response_challenge_prefix(self.method.family()).ok_or_else(|| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_completion",
                "test plugin cannot complete this proof family".to_owned(),
            )
        })
    }

    fn parse_active_method_response_subject_and_source(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<
        (SubjectId, VerifiedProofSourceId),
        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
    > {
        if challenge.proof != self.method.verified_proof_summary() {
            return Err(
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response used a different proof".to_owned(),
                ),
            );
        }
        let response_after_prefix = response
            .response_payload
            .as_bytes()
            .strip_prefix(self.response_challenge_prefix()?)
            .ok_or_else(|| {
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response payload is malformed".to_owned(),
                )
            })?;
        let nonce_len = challenge.nonce.as_bytes().len();
        if response_after_prefix.len() <= nonce_len {
            return Err(
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response payload is missing subject binding".to_owned(),
                ),
            );
        }
        let (response_nonce, response_after_nonce) = response_after_prefix.split_at(nonce_len);
        if response_nonce != challenge.nonce.as_bytes() {
            return Err(
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response nonce does not match the runtime challenge".to_owned(),
                ),
            );
        }
        let response_after_state = response_after_nonce
            .strip_prefix(b";state:")
            .and_then(|after_marker| {
                after_marker.strip_prefix(challenge.method_challenge_state.as_bytes())
            })
            .ok_or_else(|| {
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response method state does not match the sealed challenge state"
                        .to_owned(),
                )
            })?;
        let subject_and_source = response_after_state
            .strip_prefix(b";subject:")
            .ok_or_else(|| {
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response subject binding is malformed".to_owned(),
                )
            })?;
        let source_marker = b";source:";
        let source_marker_start = subject_and_source
            .windows(source_marker.len())
            .position(|window| window == source_marker)
            .ok_or_else(|| {
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response source binding is missing".to_owned(),
                )
            })?;
        let (subject_id_bytes, source_with_marker) =
            subject_and_source.split_at(source_marker_start);
        let source_id_bytes = &source_with_marker[source_marker.len()..];
        let subject_id = SubjectId::from_bytes(subject_id_bytes.to_vec()).map_err(|error| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_completion",
                error.to_string(),
            )
        })?;
        let source_id = VerifiedProofSourceId::from_bytes(source_id_bytes.to_vec()).map_err(|error| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_completion",
                error.to_string(),
            )
        })?;
        Ok((subject_id, source_id))
    }

    fn verify_active_method_response(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<
        super::super::postgres_method_runtime::VerifiedActiveProofMethodResponse,
        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
    > {
        let (subject_id, source_id) =
            self.parse_active_method_response_subject_and_source(challenge, response)?;
        let verified_proof = VerifiedActiveProof::from_summary_with_source(
            challenge.proof.clone(),
            Some(subject_id),
            test_active_method_proof_source(self.method.family(), source_id),
        )
        .map_err(|error| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_completion",
                error.to_string(),
            )
        })?;
        super::super::postgres_method_runtime::VerifiedActiveProofMethodResponse::new(
            verified_proof,
            Vec::new(),
        )
        .map_err(|error| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_completion",
                error.to_string(),
            )
        })
    }
}

fn test_challenge_presentation_prefix(family: ProofFamily) -> Option<&'static [u8]> {
    match family {
        ProofFamily::MessageSignature => Some(b"test-message-signature-challenge:"),
        ProofFamily::OriginBoundPublicKey => Some(
            b"test-origin-bound-public-key-challenge:rp=example.test;origin=https://example.test;nonce:",
        ),
        ProofFamily::FederatedIdentityAssertion => Some(
            b"test-federated-identity-state:issuer=https://issuer.example;audience=paranoid-client;redirect=https://app.example/auth/callback;state:",
        ),
        _ => None,
    }
}

fn test_active_method_proof_source(
    family: ProofFamily,
    source_id: VerifiedProofSourceId,
) -> VerifiedProofSource {
    let source_kind = match family {
        ProofFamily::MessageSignature | ProofFamily::OriginBoundPublicKey => {
            VerifiedProofSourceKind::CredentialInstance
        }
        ProofFamily::FederatedIdentityAssertion => VerifiedProofSourceKind::ExternalAuthority,
        other => panic!("unexpected active method proof family {other:?}"),
    };
    VerifiedProofSource::new(source_kind, source_id)
}

fn test_known_subject_method_proof_source(
    family: ProofFamily,
    subject_id: &SubjectId,
) -> Option<VerifiedProofSource> {
    match family {
        ProofFamily::SharedSecretOtp | ProofFamily::RecoveryCode => {
            let mut source_id = b"known-subject-method-source:".to_vec();
            source_id.extend_from_slice(format!("{family:?}:").as_bytes());
            source_id.extend_from_slice(subject_id.as_bytes());
            Some(VerifiedProofSource::new(
                VerifiedProofSourceKind::CredentialInstance,
                VerifiedProofSourceId::from_bytes(source_id)
                    .expect("known-subject test method source id"),
            ))
        }
        _ => None,
    }
}

fn test_active_method_source_id(
    family: ProofFamily,
    subject_id: &SubjectId,
) -> VerifiedProofSourceId {
    let prefix = match family {
        ProofFamily::MessageSignature => b"message-signature-key:".as_slice(),
        ProofFamily::OriginBoundPublicKey => b"origin-bound-public-key-credential:".as_slice(),
        ProofFamily::FederatedIdentityAssertion => {
            b"federated-identity-subject-mapping:".as_slice()
        }
        other => panic!("unexpected active method proof family {other:?}"),
    };
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(subject_id.as_bytes());
    VerifiedProofSourceId::from_bytes(bytes).expect("test active method source id")
}

fn test_response_challenge_prefix(family: ProofFamily) -> Option<&'static [u8]> {
    match family {
        ProofFamily::MessageSignature => Some(b"test-message-signature-response:nonce:"),
        ProofFamily::OriginBoundPublicKey => Some(
            b"test-origin-bound-public-key-response:rp=example.test;origin=https://example.test;nonce:",
        ),
        ProofFamily::FederatedIdentityAssertion => Some(
            b"test-federated-identity-assertion:issuer=https://issuer.example;audience=paranoid-client;redirect=https://app.example/auth/callback;state:",
        ),
        _ => None,
    }
}

fn test_method_runtime_challenge_bytes(
    method_challenge: &ActiveProofMethodChallengePresentation,
    family: ProofFamily,
) -> &[u8] {
    method_challenge
        .as_bytes()
        .strip_prefix(
            test_challenge_presentation_prefix(family).expect("test method challenge prefix"),
        )
        .expect("method challenge presentation must contain runtime nonce")
}

fn test_method_response_payload(
    family: ProofFamily,
    nonce: &[u8],
    subject_id: &SubjectId,
) -> ActiveProofMethodResponsePayload {
    test_method_response_payload_with_prefix(
        test_response_challenge_prefix(family).expect("test method response prefix"),
        family,
        nonce,
        subject_id,
    )
}

fn test_method_response_payload_with_prefix(
    response_prefix: &[u8],
    family: ProofFamily,
    nonce: &[u8],
    subject_id: &SubjectId,
) -> ActiveProofMethodResponsePayload {
    let mut response_payload = response_prefix.to_vec();
    response_payload.extend_from_slice(nonce);
    response_payload.extend_from_slice(b";subject:");
    response_payload.extend_from_slice(subject_id.as_bytes());
    response_payload.extend_from_slice(b";source:");
    response_payload.extend_from_slice(test_active_method_source_id(family, subject_id).as_bytes());
    ActiveProofMethodResponsePayload::try_from_bytes(response_payload)
        .expect("test method response payload")
}

fn mismatched_runtime_challenge_test_method_response_payload(
    family: ProofFamily,
    nonce: &[u8],
    subject_id: &SubjectId,
) -> ActiveProofMethodResponsePayload {
    let mut mismatched_nonce = nonce.to_vec();
    let first = mismatched_nonce
        .first_mut()
        .expect("runtime challenge nonce is non-empty");
    *first ^= 0x01;
    test_method_response_payload(family, &mismatched_nonce, subject_id)
}

fn mismatched_federated_issuer_test_method_response_payload(
    nonce: &[u8],
    subject_id: &SubjectId,
) -> ActiveProofMethodResponsePayload {
    test_method_response_payload_with_prefix(
        b"test-federated-identity-assertion:issuer=https://evil.example;audience=paranoid-client;redirect=https://app.example/auth/callback;state:",
        ProofFamily::FederatedIdentityAssertion,
        nonce,
        subject_id,
    )
}

fn known_subject_test_method_response_payload(
    subject_id: &SubjectId,
) -> KnownSubjectActiveProofSecretResponse {
    let mut payload = b"test-known-subject-proof:subject:".to_vec();
    payload.extend_from_slice(subject_id.as_bytes());
    KnownSubjectActiveProofSecretResponse::try_from_bytes(payload)
        .expect("known-subject test method response payload")
}

fn mismatched_known_subject_test_method_response_payload() -> KnownSubjectActiveProofSecretResponse
{
    let mut payload = b"test-known-subject-proof:subject:".to_vec();
    payload.extend_from_slice(b"other-subject");
    KnownSubjectActiveProofSecretResponse::try_from_bytes(payload)
        .expect("mismatched known-subject test method response payload")
}

fn test_totp_code_bytes(secret: &[u8], now: UnixSeconds) -> Vec<u8> {
    let mut payload = b"test-totp-code:".to_vec();
    payload.extend_from_slice(secret);
    payload.extend_from_slice(b":step:");
    payload.extend_from_slice(&(now.get() / 30).to_string().into_bytes());
    payload
}

fn totp_test_method_response_payload(
    secret: &[u8],
    now: UnixSeconds,
) -> KnownSubjectActiveProofSecretResponse {
    KnownSubjectActiveProofSecretResponse::try_from_bytes(test_totp_code_bytes(secret, now))
        .expect("totp test method response payload")
}

fn mismatched_totp_test_method_response_payload() -> KnownSubjectActiveProofSecretResponse {
    KnownSubjectActiveProofSecretResponse::try_from_bytes(b"test-totp-code:wrong".as_slice())
        .expect("mismatched totp test method response payload")
}

fn mismatched_recovery_code_test_method_response_payload() -> KnownSubjectActiveProofSecretResponse
{
    KnownSubjectActiveProofSecretResponse::try_from_bytes(b"wrong-recovery-code".as_slice())
        .expect("mismatched recovery code test method response payload")
}

fn minimum_accepted_password_kdf_params_for_tests() -> PasswordKdfParams {
    PasswordKdfParams::new(
        PASSWORD_KDF_MIN_MEMORY_COST_KIB,
        PASSWORD_KDF_MIN_ITERATIONS,
        1,
    )
    .expect("minimum accepted password KDF params")
}

fn guessed_recovery_code_test_method_response_payload() -> KnownSubjectActiveProofSecretResponse {
    KnownSubjectActiveProofSecretResponse::try_from_bytes(b"1111111111111111".as_slice())
        .expect("guessed recovery code test method response payload")
}

async fn validate_test_method_table_exists(
    tx: &mut Tx<'_>,
    table: &PgQualifiedTableName,
) -> Result<(), super::super::postgres_store::PostgresAuthMethodCommitError> {
    let schema = table
        .schema()
        .expect("test method table must be schema-qualified")
        .as_str();
    let table_name = table.table().as_str();
    let statement = r#"
        SELECT count(*)
        FROM information_schema.tables
        WHERE table_schema = $1 AND table_name = $2
    "#;
    tx.record_database_operation(
        crate::db::DatabaseOperationKind::FetchOne,
        "auth_core.test_method.schema.validate_table",
        Some(statement),
    );
    let count = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement))
        .bind(schema)
        .bind(table_name)
        .fetch_one(tx.sqlx_transaction().as_mut())
        .await
        .map_err(crate::db::DbError::query)?;
    if count == 1 {
        Ok(())
    } else {
        Err(
            super::super::postgres_store::PostgresAuthMethodCommitError::InvalidOperation(format!(
                "missing test method table {}",
                table.quoted()
            )),
        )
    }
}

impl super::super::postgres_method_runtime::PostgresAuthMethodPlugin
    for TestPostgresAuthMethodPlugin
{
    fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    fn build_out_of_band_issue(
        &self,
        _request: &IssueOutOfBandChallengeRequest,
    ) -> Result<
        super::super::postgres_method_runtime::PostgresOutOfBandChallengeIssueBuild,
        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
    > {
        Ok(
            super::super::postgres_method_runtime::PostgresOutOfBandChallengeIssueBuild::new(
                ActiveProofChallengeResponseSecret::try_from(b"123456".as_slice())
                    .expect("test response secret"),
                vec![out_of_band_method_commit_work()],
            ),
        )
    }

    fn build_active_proof_method_challenge<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        request: &'a IssueActiveProofMethodChallengeRequest,
        challenge: &'a ActiveProofMethodChallengeSeed,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::postgres_method_runtime::ActiveProofMethodChallengeBuild,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if request.method != self.method {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_method_challenge_issue",
                        "active proof challenge issue used a different method".to_owned(),
                    ),
                );
            }
            if challenge.proof != self.method.verified_proof_summary() {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_method_challenge_issue",
                        "active proof challenge material used a different proof".to_owned(),
                    ),
                );
            }
            let mut method_challenge_state = b"sealed-method-state:".to_vec();
            method_challenge_state.extend_from_slice(challenge.nonce.as_bytes());
            let method_challenge_state =
                ActiveProofMethodChallengeState::try_from_bytes(method_challenge_state).map_err(
                    |error| {
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                            self.method(),
                            "active_proof_method_challenge_issue",
                            error.to_string(),
                        )
                    },
                )?;
            let mut presentation = self.challenge_presentation_prefix()?.to_vec();
            presentation.extend_from_slice(challenge.nonce.as_bytes());
            presentation.extend_from_slice(b";state:");
            presentation.extend_from_slice(method_challenge_state.as_bytes());
            let presentation =
                ActiveProofMethodChallengePresentation::try_from_bytes(presentation).map_err(
                    |error| {
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                            self.method(),
                            "active_proof_method_challenge_issue",
                            error.to_string(),
                        )
                    },
                )?;
            Ok(
                super::super::postgres_method_runtime::ActiveProofMethodChallengeBuild::new(
                    presentation,
                    method_challenge_state,
                    Vec::new(),
                ),
            )
        })
    }

    fn verify_active_proof_method_response_before_state_load(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<
        super::super::postgres_method_runtime::ActiveProofMethodPreStateVerification,
        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
    > {
        self.parse_active_method_response_subject_and_source(challenge, response)?;
        match self.active_method_verification_mode {
            TestActiveMethodVerificationMode::BeforeStateLoad => Ok(
                super::super::postgres_method_runtime::ActiveProofMethodPreStateVerification::Accepted(
                    self.verify_active_method_response(challenge, response)?,
                ),
            ),
            TestActiveMethodVerificationMode::AuthoritativeConfirmation => Ok(
                super::super::postgres_method_runtime::ActiveProofMethodPreStateVerification::AcceptedNeedsAuthoritativeConfirmation(
                    self.verify_active_method_response(challenge, response)?,
                ),
            ),
        }
    }

    fn verify_active_proof_method_response_with_authoritative_state<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        context: super::super::postgres_method_runtime::ActiveProofMethodAuthoritativeVerificationContext<'a>,
        pre_state_verified: &'a super::super::postgres_method_runtime::VerifiedActiveProofMethodResponse,
        response: &'a CompleteActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::postgres_method_runtime::ActiveProofMethodAuthoritativeConfirmation,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    >{
        Box::pin(async move {
            if context.attempt_record().attempt_id != context.challenge().attempt_id {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_authoritative_confirmation",
                        "loaded attempt does not match the sealed challenge".to_owned(),
                    ),
                );
            }
            if context.challenge_record().challenge_id != context.challenge().challenge_id {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_authoritative_confirmation",
                        "loaded challenge does not match the sealed challenge".to_owned(),
                    ),
                );
            }
            if context.challenge_record().proof != context.challenge().proof {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_authoritative_confirmation",
                        "loaded challenge proof does not match the sealed challenge".to_owned(),
                    ),
                );
            }
            let expected_verified =
                self.verify_active_method_response(context.challenge(), response)?;
            if pre_state_verified != &expected_verified {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_authoritative_confirmation",
                        "pre-state proof verification changed before authoritative confirmation"
                            .to_owned(),
                    ),
                );
            }
            Ok(super::super::postgres_method_runtime::ActiveProofMethodAuthoritativeConfirmation::new(
                Vec::new(),
            ))
        })
    }

    fn verify_known_subject_active_proof_method_response<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        subject_id: &'a SubjectId,
        response: &'a CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::postgres_method_runtime::KnownSubjectActiveProofMethodVerification,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    >{
        Box::pin(async move {
            if response.method != self.method {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "known_subject_active_proof_completion",
                        "known-subject proof completion used a different method".to_owned(),
                    ),
                );
            }
            let subject_after_prefix = response
                .secret_response
                .expose_secret()
                .strip_prefix(b"test-known-subject-proof:subject:")
                .ok_or_else(|| {
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "known_subject_active_proof_completion",
                        "known-subject proof response payload is malformed".to_owned(),
                    )
                })?;
            if subject_after_prefix != subject_id.as_bytes() {
                return Ok(
                    super::super::postgres_method_runtime::KnownSubjectActiveProofMethodVerification::Rejected,
                );
            }
            let method_commit_work = if self.method.family() == ProofFamily::RecoveryCode {
                vec![recovery_code_method_commit_work()]
            } else {
                Vec::new()
            };
            let verified_proof = match test_known_subject_method_proof_source(
                self.method.family(),
                subject_id,
            ) {
                Some(source) => VerifiedActiveProof::from_summary_with_source(
                    self.method.verified_proof_summary(),
                    None,
                    source,
                ),
                None => VerifiedActiveProof::from_summary(
                    self.method.verified_proof_summary(),
                    None,
                ),
            }
            .map_err(|error| {
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    self.method(),
                    "known_subject_active_proof_completion",
                    error.to_string(),
                )
            })?;
            Ok(super::super::postgres_method_runtime::KnownSubjectActiveProofMethodVerification::Accepted(
                super::super::postgres_method_runtime::VerifiedActiveProofMethodResponse::new(
                    verified_proof,
                    method_commit_work,
                )
                .map_err(|error| {
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "known_subject_active_proof_completion",
                        error.to_string(),
                    )
                })?,
            ))
        })
    }

    fn build_credential_reset_commit_work<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        request: super::super::postgres_method_runtime::CredentialResetMethodWorkBuildRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Vec<MethodCommitWork>,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if request.target_credential.proof_family() != self.method.family()
                || request.target_credential.method_label() != self.method.method_label()
            {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "credential_reset",
                        "credential reset target used a different method".to_owned(),
                    ),
                );
            }
            Ok(vec![
                MethodCommitWork::new(
                    self.method.verified_proof_summary(),
                    vec![
                        MethodCommitPrecondition::new(
                            "password_verifier_version_current",
                            request.method_payload.as_bytes(),
                        )
                        .expect("method work item"),
                    ],
                    vec![
                        MethodCommitMutation::new(
                            "replace_password_verifier",
                            request.method_payload.as_bytes(),
                        )
                        .expect("method work item"),
                    ],
                    Vec::new(),
                )
                .expect("credential reset method commit work"),
            ])
        })
    }

    fn build_credential_lifecycle_commit_work<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        request: super::super::postgres_method_runtime::CredentialLifecycleMethodWorkBuildRequest<
            'a,
        >,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Vec<MethodCommitWork>,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if request.target_credential.proof_family() != self.method.family()
                || request.target_credential.method_label() != self.method.method_label()
            {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "credential_lifecycle",
                        "credential lifecycle target used a different method".to_owned(),
                    ),
                );
            }
            let (precondition_operation, mutation_operation) = match request.pending_action.action {
                CredentialLifecycleAction::Replace => (
                    "replacement_candidate_current",
                    "replace_credential_from_pending_action",
                ),
                CredentialLifecycleAction::Regenerate => (
                    "regeneration_candidate_current",
                    "regenerate_credential_from_pending_action",
                ),
                _ => {
                    return Err(
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                            self.method(),
                            "credential_lifecycle",
                            "credential lifecycle action does not require method work".to_owned(),
                        ),
                    );
                }
            };
            Ok(vec![
                MethodCommitWork::new(
                    self.method.verified_proof_summary(),
                    vec![
                        MethodCommitPrecondition::new(
                            precondition_operation,
                            request.method_payload.as_bytes(),
                        )
                        .expect("method work item"),
                    ],
                    vec![
                        MethodCommitMutation::new(
                            mutation_operation,
                            request.method_payload.as_bytes(),
                        )
                        .expect("method work item"),
                    ],
                    Vec::new(),
                )
                .expect("credential lifecycle method commit work"),
            ])
        })
    }

    fn migrate_schema<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (),
                        super::super::postgres_store::PostgresAuthMethodCommitError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { self.migrate_schema_in_current_transaction(tx).await })
    }

    fn validate_schema<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (),
                        super::super::postgres_store::PostgresAuthMethodCommitError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { self.validate_schema_in_current_transaction(tx).await })
    }

    fn enforce_precondition<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        precondition: &'a MethodCommitPrecondition,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (),
                        super::super::postgres_store::PostgresAuthMethodCommitError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match precondition.operation().as_str() {
                "otp_state_absent"
                | "recovery_code_still_unused"
                | "password_verifier_version_current"
                | "replacement_candidate_current"
                | "regeneration_candidate_current" => {}
                other => Self::validate_operation(other, "otp_state_absent")?,
            }
            let statement = format!(
                "SELECT 1 FROM {} WHERE payload = $1 FOR UPDATE",
                self.state_table.quoted()
            );
            tx.record_database_operation(
                crate::db::DatabaseOperationKind::FetchOptional,
                "auth_core.test_method_commit.precondition.otp_state_absent",
                Some(statement.as_str()),
            );
            let exists = pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(precondition.payload())
                .fetch_optional(tx.sqlx_transaction().as_mut())
                .await
                .map_err(crate::db::DbError::query)?
                .is_some();
            if exists {
                Err(
                    super::super::postgres_store::PostgresAuthMethodCommitError::PreconditionFailed(
                        "method state already exists",
                    ),
                )
            } else {
                Ok(())
            }
        })
    }

    fn apply_mutation<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        mutation: &'a MethodCommitMutation,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (),
                        super::super::postgres_store::PostgresAuthMethodCommitError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match mutation.operation().as_str() {
                "store_otp_state"
                | "consume_recovery_code"
                | "replace_password_verifier"
                | "replace_credential_from_pending_action"
                | "regenerate_credential_from_pending_action" => {}
                other => Self::validate_operation(other, "store_otp_state")?,
            }
            if matches!(self.failure_mode, TestMethodCommitFailureMode::FailMutation) {
                return Err(
                    super::super::postgres_store::PostgresAuthMethodCommitError::InvalidOperation(
                        "forced_mutation_failure".to_owned(),
                    ),
                );
            }
            let statement = format!(
                r#"
                INSERT INTO {} (
                    payload, proof_family, method_label, mutation_operation
                )
                VALUES ($1,$2,$3,$4)
                "#,
                self.state_table.quoted()
            );
            tx.record_database_operation(
                crate::db::DatabaseOperationKind::Execute,
                "auth_core.test_method_commit.mutation.store_otp_state",
                Some(statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(mutation.payload())
                .bind(super::super::postgres_store::i32_from_proof_family(
                    work.proof().family(),
                ))
                .bind(work.proof().method_label())
                .bind(mutation.operation().as_str())
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(crate::db::DbError::query)?;
            Ok(())
        })
    }

    fn append_durable_effect_command<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        command: &'a MethodCommitDurableEffectCommand,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (),
                        super::super::postgres_store::PostgresAuthMethodCommitError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Self::validate_operation(command.operation().as_str(), "queue_email_body")?;
            if matches!(
                self.failure_mode,
                TestMethodCommitFailureMode::FailDurableEffectCommand
            ) {
                return Err(
                    super::super::postgres_store::PostgresAuthMethodCommitError::InvalidOperation(
                        "forced_durable_effect_failure".to_owned(),
                    ),
                );
            }
            let statement = format!(
                r#"
                INSERT INTO {} (
                    payload, proof_family, method_label, durable_effect_operation
                )
                VALUES ($1,$2,$3,$4)
                "#,
                self.durable_effect_table.quoted()
            );
            tx.record_database_operation(
                crate::db::DatabaseOperationKind::Execute,
                "auth_core.test_method_commit.effect.queue_email_body",
                Some(statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(command.payload())
                .bind(super::super::postgres_store::i32_from_proof_family(
                    work.proof().family(),
                ))
                .bind(work.proof().method_label())
                .bind(command.operation().as_str())
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(crate::db::DbError::query)?;
            Ok(())
        })
    }
}

#[test]
fn postgres_method_registry_rejects_duplicate_method_registration() {
    let schema = PgSchemaName::from_identifier_text("__paranoid_auth_registry_test")
        .expect("test schema name");
    let left: Arc<dyn super::super::postgres_method_runtime::PostgresAuthMethodPlugin> = Arc::new(
        TestPostgresAuthMethodPlugin::new(&schema, TestMethodCommitFailureMode::None),
    );
    let right: Arc<dyn super::super::postgres_method_runtime::PostgresAuthMethodPlugin> = Arc::new(
        TestPostgresAuthMethodPlugin::new(&schema, TestMethodCommitFailureMode::None),
    );

    let error =
        super::super::postgres_method_runtime::PostgresAuthMethodRegistry::new([left, right])
            .expect_err("duplicate method plugins must be rejected");

    assert!(
        matches!(
            error,
            super::super::postgres_method_runtime::PostgresAuthMethodRegistryError::DuplicateMethod {
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
    let plugin: Arc<dyn super::super::postgres_method_runtime::PostgresAuthMethodPlugin> =
        Arc::new(TestPostgresAuthMethodPlugin::with_method(
            &schema,
            ProofMethodDeclaration::new(ProofFamily::TrustedDevice, "trusted_device")
                .expect("core-owned method declaration"),
            TestMethodCommitFailureMode::None,
        ));

    let error = super::super::postgres_method_runtime::PostgresAuthMethodRegistry::new([plugin])
        .expect_err("core-owned methods must not be registered as plugins");

    assert!(
        matches!(
            error,
            super::super::postgres_method_runtime::PostgresAuthMethodRegistryError::CoreOwnedMethod {
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

    let _runtime = auth_bootstrap
        .migrate_schema_and_build_web_runtime_after_db_bootstrap(
            &write_pool,
            pool.clone(),
            AuthWebRuntime::new(config(), auth_web_transport()),
            Arc::new(hashcash_verifier_for_test()),
        )
        .await
        .expect("migrate auth schema and build runtime");
    first_party_postgres_auth_bootstrap_for_test(db_bootstrap_config.clone())
        .validate_schema_after_db_bootstrap(&pool)
        .await
        .expect("validate auth schema through bootstrap facade");

    for table_name in [
        "auth_sessions",
        "auth_subject_state",
        "auth_email_otp_challenges",
        "auth_email_otp_delivery_commands",
        "auth_totp_verifiers",
        "auth_recovery_code_codes",
        "auth_password_signature_verifiers",
    ] {
        assert!(
            auth_runtime_test_table_exists(&pool, &schema, table_name).await,
            "expected auth bootstrap table {table_name} in DB foundation schema"
        );
    }

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

#[tokio::test]
async fn postgres_runtime_completes_message_signature_through_method_registry() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_message_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("message-signature-subject");
    let method = ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
        .expect("message signature method");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_challenge_request_payload: None,
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                &method,
            ),
        )
        .await
        .expect("issue message signature challenge through method registry");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id: issued_attempt_id,
            challenge_id: issued_challenge_id,
            proof,
            method_challenge,
            ..
        } => {
            assert_eq!(
                proof,
                &ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
            );
            (
                issued_attempt_id.clone(),
                issued_challenge_id.clone(),
                method_challenge,
            )
        }
        outcome => panic!("expected message signature challenge issue, got {outcome:?}"),
    };
    assert!(
        method_challenge.as_bytes().starts_with(
            test_challenge_presentation_prefix(ProofFamily::MessageSignature)
                .expect("message signature challenge prefix")
        )
    );
    let message_signature_nonce =
        test_method_runtime_challenge_bytes(method_challenge, ProofFamily::MessageSignature);
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();
    let bad_response_error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(40),
                response_payload: mismatched_runtime_challenge_test_method_response_payload(
                    ProofFamily::MessageSignature,
                    message_signature_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("bad message signature response must reject before authoritative state load");
    assert!(matches!(
        bad_response_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::PluginRejected {
                family: ProofFamily::MessageSignature,
                operation: "active_proof_completion",
                ..
            }
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "bad message signature response must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1,
        "bad message signature response must leave the authoritative challenge open"
    );

    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(50),
                response_payload: test_method_response_payload(
                    ProofFamily::MessageSignature,
                    message_signature_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete message signature proof through method registry");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature")
                .expect("proof"),
        }
    );
    assert!(set_cookie_headers_contain_deletion(
        completed.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(test_active_method_proof_source(
            ProofFamily::MessageSignature,
            test_active_method_source_id(ProofFamily::MessageSignature, &subject_id),
        ))
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_message_signature_after_authoritative_confirmation() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let method = ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
        .expect("message signature method");
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_authoritative_test_method(
            method.clone(),
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("authoritative-message-subject");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_challenge_request_payload: None,
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                &method,
            ),
        )
        .await
        .expect("issue authoritative message signature challenge through method registry");
    let (attempt_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            method_challenge,
            ..
        } => (attempt_id.clone(), method_challenge),
        outcome => panic!("expected message signature challenge issue, got {outcome:?}"),
    };
    let message_signature_nonce =
        test_method_runtime_challenge_bytes(method_challenge, ProofFamily::MessageSignature);
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);

    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: test_method_response_payload(
                    ProofFamily::MessageSignature,
                    message_signature_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete message signature through authoritative confirmation");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature")
                .expect("proof"),
        }
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(test_active_method_proof_source(
            ProofFamily::MessageSignature,
            test_active_method_source_id(ProofFamily::MessageSignature, &subject_id),
        ))
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_password_derived_signature_after_authoritative_recheck() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("password-signature-subject");
    let password_credential_id: VerifiedProofSourceId = id("password-signature-credential");
    let lookup_handle = b"password-signature-lookup";
    let password = b"correct-password";
    let salt = PasswordKdfSalt::from_bytes(&[11_u8; PASSWORD_KDF_SALT_SIZE]).expect("KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password,
                salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store password-derived verifier");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            challenge_id,
            proof,
            method_challenge,
            ..
        } => {
            assert_eq!(proof, &plugin.method().verified_proof_summary());
            (attempt_id.clone(), challenge_id.clone(), method_challenge)
        }
        outcome => panic!("expected password-derived signature challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let response_payload = PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
        password,
        method_challenge,
    )
    .expect("password-derived signature response");
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_active_method_completion(
        &completion_headers,
        &response_payload,
        at(30),
    );

    harness.database_operation_observer.clear();
    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("complete password-derived signature proof");

    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.password_derived_signature.verify.fetch_locked_current_verifier",
        "password-derived signature success must recheck authoritative verifier state",
    );
    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: plugin.method().verified_proof_summary(),
        }
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            password_credential_id,
        ))
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_wrong_password_derived_signature_before_database_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("wrong-password-signature-subject");
    let password_credential_id: VerifiedProofSourceId = id("wrong-password-signature-credential");
    let lookup_handle = b"wrong-password-signature-lookup";
    let salt = PasswordKdfSalt::from_bytes(&[12_u8; PASSWORD_KDF_SALT_SIZE]).expect("KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password: b"correct-password",
                salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store password-derived verifier");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            challenge_id,
            method_challenge,
            ..
        } => (challenge_id.clone(), method_challenge),
        outcome => panic!("expected password-derived signature challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let response_payload = PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
        b"wrong-password",
        method_challenge,
    )
    .expect("wrong password-derived signature response");
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_active_method_completion(
        &completion_headers,
        &response_payload,
        at(30),
    );

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect_err("wrong password-derived signature must reject before state load");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::PluginRejected {
                family: ProofFamily::MessageSignature,
                operation: "active_proof_completion",
                ..
            }
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "wrong password-derived signature must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1,
        "wrong password-derived signature must leave the authoritative challenge open",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_invalid_password_derived_weak_gate_before_database_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("invalid-gate-password-signature-subject");
    let password_credential_id: VerifiedProofSourceId =
        id("invalid-gate-password-signature-credential");
    let lookup_handle = b"invalid-gate-password-signature-lookup";
    let salt = PasswordKdfSalt::from_bytes(&[17_u8; PASSWORD_KDF_SALT_SIZE]).expect("KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password: b"correct-password",
                salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store password-derived verifier");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            challenge_id,
            method_challenge,
            ..
        } => (attempt_id.clone(), challenge_id.clone(), method_challenge),
        outcome => panic!("expected password-derived signature challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let response_payload = PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
        b"correct-password",
        method_challenge,
    )
    .expect("valid password-derived signature response");

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload,
                weak_proof_gate_response: Some(invalid_proof_of_work_gate_response()),
            },
        )
        .await
        .expect_err("invalid password-derived weak gate must reject before state load");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "invalid password-derived weak gate must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1,
        "invalid password-derived weak gate must leave the authoritative challenge open",
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_reused_password_derived_weak_gate_for_different_signature_before_database_work()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("reused-gate-password-signature-subject");
    let password_credential_id: VerifiedProofSourceId =
        id("reused-gate-password-signature-credential");
    let lookup_handle = b"reused-gate-password-signature-lookup";
    let salt = PasswordKdfSalt::from_bytes(&[15_u8; PASSWORD_KDF_SALT_SIZE]).expect("KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password: b"correct-password",
                salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store password-derived verifier");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            challenge_id,
            method_challenge,
            ..
        } => (challenge_id.clone(), method_challenge),
        outcome => panic!("expected password-derived signature challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let first_guessed_response_payload =
        PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
            b"first-wrong-password",
            method_challenge,
        )
        .expect("first guessed password-derived signature response");
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_active_method_completion(
        &completion_headers,
        &first_guessed_response_payload,
        at(30),
    );
    let second_guessed_response_payload =
        PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
            b"second-wrong-password",
            method_challenge,
        )
        .expect("second guessed password-derived signature response");

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: second_guessed_response_payload,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect_err("weak gate solved for one signature must not work for another signature");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "reused password-derived weak gate must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1,
        "reused password-derived weak gate must leave the authoritative challenge open",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_password_derived_signature_after_verifier_rotation() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("rotated-password-signature-subject");
    let password_credential_id: VerifiedProofSourceId = id("rotated-password-signature-credential");
    let lookup_handle = b"rotated-password-signature-lookup";
    let first_salt =
        PasswordKdfSalt::from_bytes(&[13_u8; PASSWORD_KDF_SALT_SIZE]).expect("first KDF salt");
    let second_salt =
        PasswordKdfSalt::from_bytes(&[14_u8; PASSWORD_KDF_SALT_SIZE]).expect("second KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password: b"old-password",
                salt: first_salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store old password-derived verifier");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            challenge_id,
            method_challenge,
            ..
        } => (attempt_id.clone(), challenge_id.clone(), method_challenge),
        outcome => panic!("expected password-derived signature challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let response_payload = PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
        b"old-password",
        method_challenge,
    )
    .expect("password-derived signature response against sealed old verifier");
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_active_method_completion(
        &headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]),
        &response_payload,
        at(30),
    );

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password: b"new-password",
                salt: second_salt,
                params,
                now: at(25),
            },
        )
        .await
        .expect("rotate password-derived verifier");

    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect_err("stale password-derived signature challenge must reject after recheck");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::PluginRejected {
                family: ProofFamily::MessageSignature,
                operation: "active_proof_authoritative_confirmation",
                ..
            }
        )
    ));
    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.password_derived_signature.verify.fetch_locked_current_verifier",
        "stale password-derived signature challenge must perform authoritative verifier recheck",
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authoritative_active_method_loads_resolved_subject_revocation() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let method = ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
        .expect("message signature method");
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_authoritative_test_method(
            method.clone(),
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("authoritative-revoked-subject");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_challenge_request_payload: None,
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                &method,
            ),
        )
        .await
        .expect("issue authoritative message signature challenge through method registry");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            challenge_id,
            method_challenge,
            ..
        } => (attempt_id.clone(), challenge_id.clone(), method_challenge),
        outcome => panic!("expected message signature challenge issue, got {outcome:?}"),
    };
    let message_signature_nonce =
        test_method_runtime_challenge_bytes(method_challenge, ProofFamily::MessageSignature);
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    runtime
        .execute_from_headers(
            &empty_headers,
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(25),
                subject_id: subject_id.clone(),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("commit subject-wide revocation before authoritative method completion");
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);

    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: test_method_response_payload(
                    ProofFamily::MessageSignature,
                    message_signature_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("resolved subject revocation must reject active method completion");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofAttemptNotOpen
        )
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_active_method_cookie_without_sealed_method_state() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_message_signature_method().await;
    let runtime = &harness.runtime;
    let nonce = ActiveProofChallengeFastFailNonce::from_bytes(
        &[77_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
    )
    .expect("nonce");
    let challenge_cookie = ActiveProofChallengeCookieDraft::new_without_response_mac(
        ActiveProofChallengeCookieContext::new(
            id("missing-method-state-attempt"),
            id("missing-method-state-challenge"),
            ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
            at(20),
            at(60),
            nonce.clone(),
        )
        .expect("challenge cookie context"),
    )
    .expect("challenge cookie without method state");
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofChallengeCookie(challenge_cookie),
    ]);
    let set_cookie_headers = auth_web_transport()
        .render_set_cookie_headers(at(20), effects)
        .expect("set cookie headers");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        &set_cookie_headers,
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair]);

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: test_method_response_payload(
                    ProofFamily::MessageSignature,
                    nonce.as_bytes(),
                    &id("missing-method-state-subject"),
                ),
                weak_proof_gate_response: Some(invalid_proof_of_work_gate_response()),
            },
        )
        .await
        .expect_err("active method cookie without sealed state must be rejected");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::MissingActiveProofMethodChallengeState
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "active method cookie without sealed method state must reject before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_expired_active_method_cookie_before_plugin_dispatch() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_message_signature_method().await;
    let runtime = &harness.runtime;
    let nonce = ActiveProofChallengeFastFailNonce::from_bytes(
        &[78_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
    )
    .expect("nonce");
    let challenge_cookie = ActiveProofChallengeCookieDraft::new_with_method_challenge_state(
        ActiveProofChallengeCookieContext::new(
            id("expired-active-method-attempt"),
            id("expired-active-method-challenge"),
            ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
            at(20),
            at(30),
            nonce,
        )
        .expect("challenge cookie context"),
        ActiveProofMethodChallengeState::try_from_bytes(b"expired-active-method-state".as_slice())
            .expect("method challenge state"),
    )
    .expect("expired active-method challenge cookie");
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofChallengeCookie(challenge_cookie),
    ]);
    let set_cookie_headers = auth_web_transport()
        .render_set_cookie_headers(at(20), effects)
        .expect("set cookie headers");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        &set_cookie_headers,
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair]);

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(31),
                response_payload: ActiveProofMethodResponsePayload::try_from_bytes(
                    b"malformed-response".as_slice(),
                )
                .expect("method response payload"),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("expired active-method cookie must be rejected before plugin dispatch");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofChallengeCookieExpired
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "expired active method cookie must reject before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_origin_bound_public_key_through_method_registry() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_origin_bound_public_key_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("origin-bound-public-key-subject");
    let method = ProofMethodDeclaration::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
        .expect("origin-bound public-key method");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_challenge_request_payload: None,
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                &method,
            ),
        )
        .await
        .expect("issue origin-bound public-key challenge through method registry");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id: issued_attempt_id,
            challenge_id: issued_challenge_id,
            proof,
            method_challenge,
            ..
        } => {
            assert_eq!(
                proof,
                &ProofSummary::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
                    .expect("proof"),
            );
            (
                issued_attempt_id.clone(),
                issued_challenge_id.clone(),
                method_challenge,
            )
        }
        outcome => panic!("expected origin-bound public-key challenge issue, got {outcome:?}"),
    };
    assert!(
        method_challenge.as_bytes().starts_with(
            test_challenge_presentation_prefix(ProofFamily::OriginBoundPublicKey)
                .expect("origin-bound public-key challenge prefix")
        )
    );
    let origin_bound_nonce =
        test_method_runtime_challenge_bytes(method_challenge, ProofFamily::OriginBoundPublicKey);
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let mismatched_nonce_error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: mismatched_runtime_challenge_test_method_response_payload(
                    ProofFamily::OriginBoundPublicKey,
                    origin_bound_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("origin-bound public-key assertion must bind the runtime nonce");
    assert!(matches!(
        mismatched_nonce_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
    ));
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(35),
                response_payload: test_method_response_payload(
                    ProofFamily::OriginBoundPublicKey,
                    origin_bound_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete origin-bound public-key proof through method registry");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
                .expect("proof"),
        }
    );
    assert!(set_cookie_headers_contain_deletion(
        completed.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(test_active_method_proof_source(
            ProofFamily::OriginBoundPublicKey,
            test_active_method_source_id(ProofFamily::OriginBoundPublicKey, &subject_id),
        ))
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_federated_identity_through_method_registry() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_federated_identity_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("federated-identity-subject");
    let method =
        ProofMethodDeclaration::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
            .expect("federated identity method");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_challenge_request_payload: None,
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                &method,
            ),
        )
        .await
        .expect("issue federated identity state through method registry");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id: issued_attempt_id,
            challenge_id: issued_challenge_id,
            proof,
            method_challenge,
            ..
        } => {
            assert_eq!(
                proof,
                &ProofSummary::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
                    .expect("proof"),
            );
            (
                issued_attempt_id.clone(),
                issued_challenge_id.clone(),
                method_challenge,
            )
        }
        outcome => panic!("expected federated identity state issue, got {outcome:?}"),
    };
    assert!(
        method_challenge.as_bytes().starts_with(
            test_challenge_presentation_prefix(ProofFamily::FederatedIdentityAssertion)
                .expect("federated identity state prefix")
        )
    );
    let federated_state = test_method_runtime_challenge_bytes(
        method_challenge,
        ProofFamily::FederatedIdentityAssertion,
    );
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let mismatched_issuer_error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: mismatched_federated_issuer_test_method_response_payload(
                    federated_state,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("federated identity assertion must bind issuer, audience, redirect, and state");
    assert!(matches!(
        mismatched_issuer_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
    ));
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(35),
                response_payload: test_method_response_payload(
                    ProofFamily::FederatedIdentityAssertion,
                    federated_state,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete federated identity proof through method registry");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
                .expect("proof"),
        }
    );
    assert!(set_cookie_headers_contain_deletion(
        completed.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(test_active_method_proof_source(
            ProofFamily::FederatedIdentityAssertion,
            test_active_method_source_id(ProofFamily::FederatedIdentityAssertion, &subject_id),
        ))
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_totp_through_known_subject_method_registry() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-known-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-known-credential");
    let totp_secret = b"totp-known-subject-secret";
    let method =
        ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp").expect("TOTP method");

    totp_plugin
        .store_secret_for_test(pool, &subject_id, &totp_credential_id, totp_secret, at(10))
        .await
        .expect("store TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-known-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let attempt_id = started.attempt_id.clone();
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let failed_secret_response = mismatched_totp_test_method_response_payload();
    let failed_weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_known_subject_completion(
            &continuation_headers,
            &method,
            &failed_secret_response,
            at(30),
        );
    let failed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(30),
                method: method.clone(),
                secret_response: failed_secret_response,
                weak_proof_gate_response: Some(failed_weak_proof_gate_response),
            },
        )
        .await
        .expect("failed TOTP proof should be recorded through the weak-proof budget");
    assert_eq!(
        failed.outcome(),
        &Outcome::ActiveProofFailureRecorded {
            attempt_id: attempt_id.clone(),
            attempt_was_deleted: false,
        }
    );
    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.totp.verify.fetch_locked_verifier",
        "wrong direct TOTP with a valid weak gate must perform authoritative verifier lookup",
    );
    assert!(failed.set_cookie_headers().is_empty());
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        fetch_active_proof_attempt_weak_failures(pool, store_config, &attempt_id).await,
        Some(1),
    );

    let completed_secret_response = totp_test_method_response_payload(totp_secret, at(85));
    let completed_weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_known_subject_completion(
            &continuation_headers,
            &method,
            &completed_secret_response,
            at(85),
        );
    let completed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(85),
                method,
                secret_response: completed_secret_response,
                weak_proof_gate_response: Some(completed_weak_proof_gate_response),
            },
        )
        .await
        .expect("complete TOTP through known-subject method registry");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::SharedSecretOtp, "totp").expect("proof"),
        }
    );
    assert!(completed.set_cookie_headers().is_empty());
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            totp_credential_id,
        ))
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_challenge_bound_totp_bloom_rejects_definite_miss_before_database_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-bloom-definite-miss-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-bloom-definite-miss-credential");
    let totp_secret = b"totp-bloom-definite-miss-secret";

    totp_plugin
        .store_secret_for_test(pool, &subject_id, &totp_credential_id, totp_secret, at(10))
        .await
        .expect("store TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-bloom-definite-miss-bootstrap",
        20,
        subject_id,
        false,
    )
    .await;
    let challenge = start_current_session_and_issue_challenge_bound_totp_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        at(80),
    )
    .await;
    let completion_headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let secret_response = mismatched_totp_test_method_response_payload();
    let weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_challenge_bound_totp_completion(
            &completion_headers,
            &secret_response,
            at(85),
        );

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
                now: at(85),
                secret_response,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect_err("definite Bloom miss must reject before authoritative state load");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::PluginRejected {
                family: ProofFamily::SharedSecretOtp,
                operation: "challenge_bound_known_subject_active_proof_completion",
                ..
            }
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "definite TOTP Bloom miss must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge.challenge_id).await,
        1,
        "definite Bloom miss must leave the authoritative challenge open"
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &challenge.attempt_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_invalid_challenge_bound_totp_weak_gate_before_database_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-bloom-invalid-gate-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-bloom-invalid-gate-credential");
    let totp_secret = b"totp-bloom-invalid-gate-secret";

    totp_plugin
        .store_secret_for_test(pool, &subject_id, &totp_credential_id, totp_secret, at(10))
        .await
        .expect("store TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-bloom-invalid-gate-bootstrap",
        20,
        subject_id,
        false,
    )
    .await;
    let challenge = start_current_session_and_issue_challenge_bound_totp_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        at(80),
    )
    .await;
    let completion_headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let secret_response = totp_test_method_response_payload(totp_secret, at(85));

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
                now: at(85),
                secret_response,
                weak_proof_gate_response: Some(invalid_proof_of_work_gate_response()),
            },
        )
        .await
        .expect_err("invalid challenge-bound TOTP weak gate must reject before state load");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "invalid challenge-bound TOTP weak gate must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge.challenge_id).await,
        1,
        "invalid challenge-bound TOTP weak gate must leave the authoritative challenge open",
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &challenge.attempt_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_challenge_bound_totp_bloom_possible_hit_completes_authoritatively() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-bloom-authoritative-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-bloom-authoritative-credential");
    let totp_secret = b"totp-bloom-authoritative-secret";

    totp_plugin
        .store_secret_for_test(pool, &subject_id, &totp_credential_id, totp_secret, at(10))
        .await
        .expect("store TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-bloom-authoritative-bootstrap",
        20,
        subject_id,
        false,
    )
    .await;
    let challenge = start_current_session_and_issue_challenge_bound_totp_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        at(80),
    )
    .await;
    assert!(
        challenge.challenge_cookie_pair.len() < 2048,
        "challenge-bound TOTP Bloom cookie pair should stay comfortably below one 4KiB cookie"
    );
    let completion_headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let secret_response = totp_test_method_response_payload(totp_secret, at(85));
    let weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_challenge_bound_totp_completion(
            &completion_headers,
            &secret_response,
            at(85),
        );

    harness.database_operation_observer.clear();
    let completed = runtime
        .execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
                now: at(85),
                secret_response,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("complete challenge-bound TOTP through Bloom lane");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: challenge.attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::SharedSecretOtp, "totp").expect("proof"),
        }
    );
    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.totp.verify.fetch_locked_verifier",
        "possible TOTP Bloom hit must perform authoritative verifier lookup",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge.challenge_id).await,
        0
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &challenge.attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            totp_credential_id,
        ))
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_challenge_bound_totp_bloom_possible_hit_rechecks_verifier_version() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-bloom-stale-verifier-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-bloom-stale-verifier-credential");
    let old_totp_secret = b"totp-bloom-stale-verifier-old-secret";
    let new_totp_secret = b"totp-bloom-stale-verifier-new-secret";

    totp_plugin
        .store_secret_for_test(
            pool,
            &subject_id,
            &totp_credential_id,
            old_totp_secret,
            at(10),
        )
        .await
        .expect("store old TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-bloom-stale-verifier-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let challenge = start_current_session_and_issue_challenge_bound_totp_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        at(80),
    )
    .await;
    let completion_headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let secret_response = totp_test_method_response_payload(old_totp_secret, at(85));
    let weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_challenge_bound_totp_completion(
            &completion_headers,
            &secret_response,
            at(85),
        );

    totp_plugin
        .store_secret_for_test(
            pool,
            &subject_id,
            &totp_credential_id,
            new_totp_secret,
            at(82),
        )
        .await
        .expect("rotate TOTP verifier state");

    harness.database_operation_observer.clear();
    let failed = runtime
        .execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
                now: at(85),
                secret_response,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("stale verifier Bloom possible hit should record a proof failure");

    assert_eq!(
        failed.outcome(),
        &Outcome::ActiveProofFailureRecorded {
            attempt_id: challenge.attempt_id.clone(),
            attempt_was_deleted: false,
        }
    );
    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.totp.verify.fetch_locked_verifier",
        "stale TOTP Bloom possible hit must perform authoritative verifier/version recheck",
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &challenge.attempt_id).await,
        0
    );
    assert_eq!(
        fetch_active_proof_attempt_weak_failures(pool, store_config, &challenge.attempt_id).await,
        Some(1)
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_challenge_bound_totp_bloom_has_no_false_negative_for_late_window_code() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-bloom-late-window-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-bloom-late-window-credential");
    let totp_secret = b"totp-bloom-late-window-secret";

    totp_plugin
        .store_secret_for_test(pool, &subject_id, &totp_credential_id, totp_secret, at(10))
        .await
        .expect("store TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-bloom-late-window-bootstrap",
        20,
        subject_id,
        false,
    )
    .await;
    let challenge = start_current_session_and_issue_challenge_bound_totp_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        at(80),
    )
    .await;
    let completion_headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let secret_response = totp_test_method_response_payload(totp_secret, at(115));
    let weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_challenge_bound_totp_completion(
            &completion_headers,
            &secret_response,
            at(115),
        );

    let completed = runtime
        .execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
                now: at(115),
                secret_response,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("late-window TOTP code must not be a Bloom false negative");

    assert!(matches!(
        completed.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &challenge.attempt_id).await,
        1
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_deletes_attempt_after_totp_failure_budget() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-budget-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-budget-credential");
    let method =
        ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp").expect("TOTP method");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-budget-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let attempt_id = started.attempt_id.clone();
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    totp_plugin
        .store_secret_for_test(
            pool,
            &subject_id,
            &totp_credential_id,
            b"totp-budget-secret",
            at(10),
        )
        .await
        .expect("store TOTP verifier state");

    for (now, attempt_was_deleted) in [(80, false), (81, false), (82, true)] {
        let secret_response = mismatched_totp_test_method_response_payload();
        let weak_proof_gate_response =
            bound_proof_of_work_gate_response_for_known_subject_completion(
                &continuation_headers,
                &method,
                &secret_response,
                at(now),
            );
        let failed = runtime
            .execute_known_subject_active_proof_method_response_from_headers(
                &continuation_headers,
                CompleteKnownSubjectActiveProofMethodResponse {
                    now: at(now),
                    method: method.clone(),
                    secret_response,
                    weak_proof_gate_response: Some(weak_proof_gate_response),
                },
            )
            .await
            .expect("failed TOTP proof should record or delete by weak-proof budget");
        assert_eq!(
            failed.outcome(),
            &Outcome::ActiveProofFailureRecorded {
                attempt_id: attempt_id.clone(),
                attempt_was_deleted,
            }
        );
    }

    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        totp_plugin
            .count_verifiers_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count TOTP verifier after weak-proof budget exhaustion"),
        1,
        "exhausting a TOTP proof ceremony must not consume or delete the configured TOTP verifier",
    );
    assert_eq!(count_all_sessions(pool, store_config).await, 1);
    let resolved_existing_session = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]),
            ResolveRequestInput {
                now: at(83),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve existing session after weak-proof budget exhaustion");
    assert_eq!(
        resolved_existing_session.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id,
            session_id: issued_auth.session_id,
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: false,
        }),
        "exhausting a TOTP proof ceremony must not lock or revoke the live session",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_invalid_totp_weak_gate_before_state_load() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "totp-invalid-gate-bootstrap",
        20,
        id("unused-invalid-gate-subject"),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(80),
                method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
                    .expect("TOTP method"),
                secret_response: mismatched_totp_test_method_response_payload(),
                weak_proof_gate_response: Some(invalid_proof_of_work_gate_response()),
            },
        )
        .await
        .expect_err("invalid weak gate must fail before loading the active proof attempt");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "invalid TOTP weak gate must reject before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_recovery_code_through_known_subject_method_registry() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("recovery-known-subject");
    let recovery_code_id = b"recovery-code-id";
    let recovery_code_secret = b"correct-recovery-code";
    let method = ProofMethodDeclaration::new(ProofFamily::RecoveryCode, "recovery_code")
        .expect("recovery code method");

    recovery_code_plugin
        .store_recovery_code_for_test(
            pool,
            &subject_id,
            recovery_code_id,
            recovery_code_secret,
            at(10),
        )
        .await
        .expect("store recovery code verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "recovery-known-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        ProofUse::RecoverOrReplaceCredential,
    )
    .await;
    let attempt_id = started.attempt_id.clone();
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let pre_state_rejected = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(80),
                method: method.clone(),
                secret_response: mismatched_recovery_code_test_method_response_payload(),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("malformed sealed recovery code must reject before state load");
    assert!(
        matches!(
            pre_state_rejected,
            super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
        ),
        "expected method pre-state rejection, got {pre_state_rejected:?}"
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "malformed sealed recovery code must reject before any database operation",
    );
    assert_eq!(
        recovery_code_plugin
            .count_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count recovery codes"),
        1
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count unused recovery codes"),
        1
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    harness.database_operation_observer.clear();
    let guessed_sealed_rejected = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(81),
                method: method.clone(),
                secret_response: guessed_recovery_code_test_method_response_payload(),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("guessed sealed recovery code must reject before state load");
    assert!(
        matches!(
            guessed_sealed_rejected,
            super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
        ),
        "expected guessed sealed code method pre-state rejection, got {guessed_sealed_rejected:?}"
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "guessed sealed recovery code must reject before any database operation",
    );
    let wrong_subject_sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&id("other-recovery-subject"), recovery_code_secret)
        .expect("wrong-subject sealed recovery code response");
    harness.database_operation_observer.clear();
    let wrong_subject_rejected = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(82),
                method: method.clone(),
                secret_response: wrong_subject_sealed_response,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("wrong-subject sealed recovery code must reject before state load");
    assert!(
        matches!(
            wrong_subject_rejected,
            super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
        ),
        "expected wrong-subject method pre-state rejection, got {wrong_subject_rejected:?}"
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "wrong-subject sealed recovery code must reject before any database operation",
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count unused recovery codes"),
        1
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    let unused_sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, b"unused-recovery-code")
        .expect("unused sealed recovery code response");
    harness.database_operation_observer.clear();
    let unused_sealed_rejection = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(83),
                method: method.clone(),
                secret_response: unused_sealed_response,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("unused sealed recovery code must reject authoritatively");
    assert_eq!(
        unused_sealed_rejection.outcome(),
        &Outcome::ActiveProofFailureRecorded {
            attempt_id: attempt_id.clone(),
            attempt_was_deleted: false,
        }
    );
    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.recovery_code.verify.fetch_locked_unused_code",
        "well-formed unused recovery code must perform authoritative one-time lookup",
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count unused recovery codes after unused sealed rejection"),
        1,
        "unused sealed recovery code must not consume any stored recovery code"
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0,
        "unused sealed recovery code must not record a satisfied proof"
    );
    assert_eq!(
        fetch_active_proof_attempt_weak_failures(pool, store_config, &attempt_id).await,
        Some(0),
        "unused sealed recovery code must not spend online-guessing weak-failure budget"
    );
    let sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, recovery_code_secret)
        .expect("sealed recovery code response");

    let completed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(85),
                method,
                secret_response: sealed_response,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete recovery code through known-subject method registry");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::RecoveryCode, "recovery_code").expect("proof"),
        }
    );
    assert!(completed.set_cookie_headers().is_empty());
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            VerifiedProofSourceId::from_bytes(recovery_code_id.as_slice())
                .expect("recovery code source id"),
        ))
    );
    assert_eq!(
        recovery_code_plugin
            .count_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count recovery codes"),
        1
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count unused recovery codes"),
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_direct_active_proof_attempt_start() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let attempt_id: ActiveProofAttemptId = id("totp-unbound-attempt");

    let error = runtime
        .execute_from_headers(
            &empty_headers,
            Command::StartActiveProofAttempt(StartActiveProofAttempt {
                now: at(20),
                attempt_id: attempt_id.clone(),
                proof_use: ProofUse::SatisfyStepUp,
                subject_id: None,
            }),
        )
        .await
        .expect_err("direct attempt start must require runtime fresh ID generation");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofAttemptStartRequiresRuntimeFreshIdGeneration
        )
    ));
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &attempt_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_current_session_active_proof_start_without_session_does_not_write() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();

    let execution = runtime
        .execute_current_session_active_proof_attempt_start_from_headers(
            &empty_headers,
            StartCurrentSessionActiveProofAttemptInput {
                now: at(20),
                proof_use: ProofUse::SatisfyStepUp,
            },
        )
        .await
        .expect("missing session resolves without writes");

    assert_eq!(execution.outcome(), &Outcome::NeedsFullAuthentication);
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_unbound_challenge_issue_preflight_before_writes() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("preflight-rejected:email-hash:window"),
                recipient_handle: "preflight-rejected-recipient".to_owned(),
                idempotency_key: "preflight-rejected-delivery".to_owned(),
            },
            invalid_challenge_issue_preflight_response(),
        )
        .await
        .expect_err("invalid challenge issue preflight must reject before writes");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "invalid challenge issue preflight must reject before any database operation",
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        0
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email otp delivery commands after rejected preflight"),
        0,
        "invalid challenge issue preflight must not enqueue method-owned delivery commands",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_unbound_challenge_issue_preflight_gate_mismatch_before_writes() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
                    .expect("method declaration"),
                method_challenge_request_payload: None,
            },
            mismatched_challenge_issue_preflight_response(),
        )
        .await
        .expect_err("mismatched challenge issue preflight gate must reject before writes");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ChallengeIssuePreflightGateMismatch
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "mismatched challenge issue preflight gate must reject before any database operation",
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_configured_secret_challenge_issue_path() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "totp-challenge-path-bootstrap",
        20,
        id("totp-challenge-path-subject"),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    let error = runtime
        .execute_active_proof_method_challenge_issue_from_headers(
            &continuation_headers,
            IssueActiveProofMethodChallengeInput {
                now: at(80),
                method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
                    .expect("TOTP method"),
                method_challenge_request_payload: None,
            },
        )
        .await
        .expect_err("TOTP must not use active-proof challenge cookie issuance");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ProofMethodCannotIssueActiveProofMethodChallenge {
                family: ProofFamily::SharedSecretOtp
            }
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_direct_active_proof_completion() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let proof = ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof");
    let direct_command = Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
        now: at(30),
        attempt_id: id("direct-message-signature-attempt"),
        challenge_id: None,
        verified_proof: VerifiedActiveProof::from_summary(proof, Some(id("direct-subject")))
            .expect("verified proof"),
        stateless_fast_fail: StatelessFastFailStatus::NotRequired,
        weak_proof_gate: WeakProofGateStatus::NotRequired,
        method_commit_work: Vec::new(),
    });

    let error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_command)
        .await
        .expect_err("runtime must not accept caller-provided verified active proofs");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofCompletionRequiresRuntimeMethodDispatch
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_direct_active_proof_failure_recording() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let direct_command = Command::RecordActiveProofFailure(RecordActiveProofFailure {
        now: at(30),
        attempt_id: id("direct-failure-attempt"),
        challenge_id: None,
        method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
            .expect("TOTP method"),
        weak_proof_gate: verified_proof_of_work_gate(),
    });

    let error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_command)
        .await
        .expect_err("runtime must not accept caller-provided active-proof failures");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofFailureRequiresRuntimeMethodDispatch
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_direct_credential_reset_commands() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let target_credential_id = id("direct-reset-password-credential");
    let direct_plan = Command::PlanCredentialReset(PlanCredentialReset {
        now: at(30),
        lifecycle_context: credential_lifecycle_context(
            message_signature_credential_metadata("direct-reset-password-credential"),
            [CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                id("direct-reset-authority"),
                RecoveryAuthorityTiming::Immediate,
            )],
            [credential_instance_lifecycle_evidence(
                "direct-reset-source",
                [id("direct-reset-authority")],
            )],
        ),
        active_proof_attempt_to_close: None,
        independent_evidence_required:
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        pending_action: None,
        immediate_subject_auth_revocation:
            CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
    });

    let plan_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_plan)
        .await
        .expect_err("runtime must not accept caller-provided credential reset lifecycle context");

    assert!(matches!(
        plan_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialResetPlanningRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_execute = Command::ExecuteCredentialReset(ExecuteCredentialReset {
        now: at(30),
        execution_authority: CredentialResetExecutionAuthority::Immediate {
            lifecycle_context: credential_lifecycle_context(
                message_signature_credential_metadata("direct-reset-password-credential"),
                [CredentialRecoveryAuthority::new(
                    target_credential_id,
                    CredentialLifecycleAction::Reset,
                    id("direct-reset-authority"),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [credential_instance_lifecycle_evidence(
                    "direct-reset-source",
                    [id("direct-reset-authority")],
                )],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        },
        method_commit_work: vec![password_reset_method_commit_work(b"direct-reset-verifier")],
        subject_auth_revocation: CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
    });

    let execute_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_execute)
        .await
        .expect_err("runtime must not accept caller-provided credential reset method work");

    assert!(matches!(
        execute_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialResetExecutionRequiresRuntimeMethodDispatch
        )
    ));

    let direct_cancel = Command::CancelPendingCredentialReset(CancelPendingCredentialReset {
        now: at(30),
        target_credential: message_signature_credential_metadata(
            "direct-reset-password-credential",
        ),
        pending_action: PendingCredentialLifecycleActionRecord::new_open(
            id("direct-reset-pending-action"),
            id("subject"),
            id("direct-reset-password-credential"),
            CredentialLifecycleAction::Reset,
            at(10),
            at(100),
            at(200),
        )
        .expect("pending reset action"),
    });

    let cancel_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_cancel)
        .await
        .expect_err("runtime must not accept caller-provided credential reset cancellation facts");

    assert!(matches!(
        cancel_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialResetCancellationRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_lifecycle_execute = Command::ExecuteNonResetPendingCredentialLifecycleAction(
        ExecuteNonResetPendingCredentialLifecycleAction {
            now: at(30),
            target_credential: message_signature_credential_metadata(
                "direct-replacement-password-credential",
            ),
            pending_action: PendingCredentialLifecycleActionRecord::new_open(
                id("direct-replacement-pending-action"),
                id("subject"),
                id("direct-replacement-password-credential"),
                CredentialLifecycleAction::Replace,
                at(10),
                at(20),
                at(200),
            )
            .expect("pending replacement action"),
            method_commit_work: vec![password_reset_method_commit_work(
                b"direct-replacement-verifier",
            )],
            subject_auth_revocation:
                CredentialLifecycleSubjectAuthRevocation::PreserveExistingAuthState,
        },
    );

    let lifecycle_execute_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_lifecycle_execute)
        .await
        .expect_err("runtime must not accept caller-provided lifecycle execution facts");

    assert!(matches!(
        lifecycle_execute_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleExecutionRequiresRuntimeMethodDispatch
        )
    ));

    let direct_lifecycle_cancel = Command::CancelNonResetPendingCredentialLifecycleAction(
        CancelNonResetPendingCredentialLifecycleAction {
            now: at(30),
            target_credential: message_signature_credential_metadata(
                "direct-replacement-password-credential",
            ),
            pending_action: PendingCredentialLifecycleActionRecord::new_open(
                id("direct-replacement-pending-action"),
                id("subject"),
                id("direct-replacement-password-credential"),
                CredentialLifecycleAction::Replace,
                at(10),
                at(100),
                at(200),
            )
            .expect("pending replacement action"),
        },
    );

    let lifecycle_cancel_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_lifecycle_cancel)
        .await
        .expect_err("runtime must not accept caller-provided lifecycle cancellation facts");

    assert!(matches!(
        lifecycle_cancel_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleCancellationRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_subject_deletion_schedule =
        Command::ScheduleSubjectAuthStateDeletion(ScheduleSubjectAuthStateDeletion {
            now: at(30),
            subject_id: id("subject"),
            pending_action: PendingSubjectLifecycleActionSchedule {
                pending_action_id: id("direct-subject-deletion-pending-action"),
                earliest_execute_at: at(100),
                expires_at: at(200),
            },
        });

    let subject_deletion_schedule_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_subject_deletion_schedule)
        .await
        .expect_err("runtime must not accept caller-provided subject deletion schedule facts");

    assert!(matches!(
        subject_deletion_schedule_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::SubjectAuthStateDeletionSchedulingRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_subject_deletion_pending_action = PendingSubjectLifecycleActionRecord::new_open(
        id("direct-subject-deletion-pending-action"),
        id("subject"),
        SubjectLifecycleAction::DeleteSubjectAuthState,
        at(10),
        at(20),
        at(200),
    )
    .expect("pending subject deletion action");

    let direct_subject_deletion_execute =
        Command::ExecutePendingSubjectAuthStateDeletion(ExecutePendingSubjectAuthStateDeletion {
            now: at(30),
            pending_action: direct_subject_deletion_pending_action.clone(),
        });

    let subject_deletion_execute_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_subject_deletion_execute)
        .await
        .expect_err("runtime must not accept caller-provided subject deletion execution facts");

    assert!(matches!(
        subject_deletion_execute_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::SubjectAuthStateDeletionExecutionRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_subject_deletion_cancel =
        Command::CancelPendingSubjectAuthStateDeletion(CancelPendingSubjectAuthStateDeletion {
            now: at(30),
            pending_action: direct_subject_deletion_pending_action,
        });

    let subject_deletion_cancel_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_subject_deletion_cancel)
        .await
        .expect_err("runtime must not accept caller-provided subject deletion cancellation facts");

    assert!(matches!(
        subject_deletion_cancel_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::SubjectAuthStateDeletionCancellationRequiresRuntimeLifecycleDecision
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_reset_planning_builds_lifecycle_context_internally()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-reset-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-reset-plan-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-reset-plan-password");
    let session_authority = id("authenticated-reset-plan-session-authority");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let execution = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                pending_action_timing: None,
                immediate_subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect("plan authenticated credential reset");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialResetPlanned(CredentialResetOutcome::AuthorizedImmediate {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id.clone(),
        })
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential reset planning must atomically schedule an authorization notice"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_target(
            pool,
            store_config,
            &target_credential_id,
        )
        .await,
        0,
        "immediate reset planning must not create a pending action"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_reset_planning_generates_pending_action_internally()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-delayed-reset-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-delayed-reset-plan-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-delayed-reset-password");
    let session_authority = id("authenticated-delayed-reset-session-authority");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                session_authority.clone(),
                RecoveryAuthorityTiming::Delayed,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let execution = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                pending_action_timing: Some(CredentialResetPendingActionTiming {
                    earliest_execute_at: at(200),
                    expires_at: at(300),
                }),
                immediate_subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect("plan delayed authenticated credential reset");

    let pending_action_id = match execution.outcome() {
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            subject_id: actual_subject_id,
            target_credential_instance_id,
            pending_action_id,
            earliest_execute_at,
            expires_at,
        }) => {
            assert_eq!(actual_subject_id, &subject_id);
            assert_eq!(target_credential_instance_id, &target_credential_id);
            assert_eq!(earliest_execute_at, &at(200));
            assert_eq!(expires_at, &at(300));
            pending_action_id.clone()
        }
        outcome => panic!("expected pending reset action, got {outcome:?}"),
    };
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        1,
        "runtime-generated pending action id must be committed"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_reschedules_reset_after_expiry_with_quiet_cleanup() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-expired-reset-reschedule-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-expired-reset-reschedule-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-expired-reset-password");
    let session_authority = id("authenticated-expired-reset-session-authority");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                session_authority.clone(),
                RecoveryAuthorityTiming::Delayed,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let expired_planned = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                pending_action_timing: Some(CredentialResetPendingActionTiming {
                    earliest_execute_at: at(82),
                    expires_at: at(83),
                }),
                immediate_subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect("plan soon-expiring authenticated credential reset");
    let expired_pending_action_id = match expired_planned.outcome() {
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            pending_action_id,
            ..
        }) => pending_action_id.clone(),
        outcome => panic!("expected pending reset action, got {outcome:?}"),
    };
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &expired_pending_action_id,
        )
        .await,
        1,
        "first pending reset starts open"
    );

    let replacement_planned = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(84),
                target_credential_instance_id: target_credential_id.clone(),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                pending_action_timing: Some(CredentialResetPendingActionTiming {
                    earliest_execute_at: at(200),
                    expires_at: at(300),
                }),
                immediate_subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect("expired pending reset must not block replacement scheduling");
    let replacement_pending_action_id = match replacement_planned.outcome() {
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            pending_action_id,
            ..
        }) => pending_action_id.clone(),
        outcome => panic!("expected replacement pending reset action, got {outcome:?}"),
    };

    assert_eq!(
        pending_credential_reset_closed_at_for_pending_action(
            pool,
            store_config,
            &expired_pending_action_id,
        )
        .await,
        Some(84),
        "expired pending reset cleanup is a quiet close at transition time"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &replacement_pending_action_id,
        )
        .await,
        1,
        "replacement pending reset remains open"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_credential_reset_cancellation_closes_open_action() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-reset-cancel-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-reset-cancel-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-reset-cancel-password");
    let session_authority = id("authenticated-reset-cancel-session-authority");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                session_authority.clone(),
                RecoveryAuthorityTiming::Delayed,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let planned = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                pending_action_timing: Some(CredentialResetPendingActionTiming {
                    earliest_execute_at: at(200),
                    expires_at: at(300),
                }),
                immediate_subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect("plan delayed authenticated credential reset");
    let pending_action_id = match planned.outcome() {
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            pending_action_id,
            ..
        }) => pending_action_id.clone(),
        outcome => panic!("expected pending reset action, got {outcome:?}"),
    };

    let cancellation = runtime
        .execute_authenticated_pending_credential_reset_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialResetInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("cancel pending credential reset");

    assert_eq!(
        cancellation.outcome(),
        &Outcome::CredentialResetPendingActionCancelled(CredentialResetCancellationOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id,
            pending_action_id: pending_action_id.clone(),
        })
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        0,
        "cancellation must close the pending reset action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        2,
        "scheduling and cancellation must both commit security notices"
    );

    let replay_error = runtime
        .execute_authenticated_pending_credential_reset_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialResetInput {
                now: at(95),
                pending_action_id,
            },
        )
        .await
        .expect_err("closed pending reset cancellation must not replay");

    assert!(matches!(
        replay_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingCredentialLifecycleActionNotCancellable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_planning_consumes_recovery_attempt() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("unauthenticated-reset-plan-subject");
    let target_credential_id = id("unauthenticated-reset-plan-password");
    let recovery_authority = id("unauthenticated-reset-plan-recovery-authority");
    let recovery_code_id = b"recovery-plan-id";
    let recovery_code_secret = b"correct-recovery";
    let recovery_code_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::CredentialInstance,
        VerifiedProofSourceId::from_bytes(recovery_code_id.as_slice())
            .expect("recovery code source id"),
    );
    recovery_code_plugin
        .store_recovery_code_for_test(
            pool,
            &subject_id,
            recovery_code_id,
            recovery_code_secret,
            at(10),
        )
        .await
        .expect("store recovery code verifier state");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                recovery_authority.clone(),
                RecoveryAuthorityTiming::Delayed,
            )],
            &[LifecycleAuthorityEvidence::from_verified_proof_source(
                recovery_code_source,
                [recovery_authority],
            )
            .expect("recovery code lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "unauthenticated-reset-plan-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        ProofUse::RecoverOrReplaceCredential,
    )
    .await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);
    let sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, recovery_code_secret)
        .expect("sealed recovery code response");
    runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(80),
                method: ProofMethodDeclaration::new(ProofFamily::RecoveryCode, "recovery_code")
                    .expect("recovery code method"),
                secret_response: sealed_response,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete recovery code proof");

    let execution = runtime
        .execute_unauthenticated_credential_reset_planning_from_headers(
            &continuation_headers,
            PlanUnauthenticatedCredentialResetInput {
                now: at(90),
                target_credential_instance_id: target_credential_id.clone(),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                pending_action_timing: Some(CredentialResetPendingActionTiming {
                    earliest_execute_at: at(200),
                    expires_at: at(300),
                }),
                immediate_subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect("plan unauthenticated credential reset");

    let pending_action_id = match execution.outcome() {
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            subject_id: actual_subject_id,
            target_credential_instance_id,
            pending_action_id,
            ..
        }) => {
            assert_eq!(actual_subject_id, &subject_id);
            assert_eq!(target_credential_instance_id, &target_credential_id);
            pending_action_id.clone()
        }
        outcome => panic!("expected pending reset action, got {outcome:?}"),
    };
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        1,
        "recovery planning must create the pending action inside the runtime commit"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &started.attempt_id).await,
        0,
        "recovery planning must consume the active-proof attempt it used as lifecycle evidence"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_reset_builds_method_work_internally() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            true,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature reset method plugin");
    let subject_id = id("authenticated-reset-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-reset-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-reset-password-credential");
    let session_authority = id("authenticated-reset-session-authority");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let execution = runtime
        .execute_authenticated_credential_reset_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"new-authenticated-password-verifier".as_slice(),
                )
                .expect("reset payload"),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect("execute authenticated credential reset");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id,
            pending_action_id: None,
        })
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "method-owned verifier work must be committed through the registered plugin"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential reset execution must atomically schedule a security notice"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_credential_reset_builds_method_work_internally() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature reset method plugin");
    let subject_id = id("pending-reset-subject");
    let target_credential_id = id("pending-reset-password-credential");
    let email_authority = id("pending-reset-email-authority");
    let pending_action_id = id("pending-reset-action");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                email_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_pending_credential_reset_for_runtime_test(
        pool,
        &seed_store,
        target_credential_id.clone(),
        email_authority,
        pending_action_id.clone(),
    )
    .await;

    let execution = runtime
        .execute_mature_pending_credential_reset_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialResetInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"new-pending-password-verifier".as_slice(),
                )
                .expect("reset payload"),
                subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect("execute mature pending credential reset");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id,
            pending_action_id: Some(pending_action_id.clone()),
        })
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "pending reset method work must be committed through the registered plugin"
    );

    let replay_error = runtime
        .execute_mature_pending_credential_reset_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialResetInput {
                now: at(260),
                pending_action_id,
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"new-pending-password-verifier".as_slice(),
                )
                .expect("reset payload"),
                subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect_err("closed pending credential reset must not replay");

    assert!(matches!(
        replay_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingCredentialLifecycleActionNotExecutable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_credential_replacement_builds_method_work_internally() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature lifecycle method plugin");
    let subject_id = id("pending-replacement-subject");
    let target_credential_id = id("pending-replacement-password-credential");
    let pending_action_id = id("pending-replacement-action");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Replace,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending replacement action")],
        )
        .await
        .expect("seed pending replacement action");

    let execution = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: Some(
                    CredentialLifecycleMethodPayload::try_from_bytes(
                        b"replacement-verifier".as_slice(),
                    )
                    .expect("lifecycle payload"),
                ),
                subject_auth_revocation:
                    CredentialLifecycleSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect("execute mature pending credential replacement");

    assert_eq!(
        execution.outcome(),
        &Outcome::NonResetPendingCredentialLifecycleActionExecuted(
            NonResetPendingCredentialLifecycleActionExecutionOutcome {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Replace,
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "pending replacement method work must be committed through the registered plugin"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Superseded,
        "replacement execution must supersede the old target credential"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Replace,
        )
        .await,
        0,
        "replacement execution must close the pending action"
    );

    let replay_error = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(260),
                pending_action_id,
                method_payload: Some(
                    CredentialLifecycleMethodPayload::try_from_bytes(
                        b"replacement-verifier".as_slice(),
                    )
                    .expect("lifecycle payload"),
                ),
                subject_auth_revocation:
                    CredentialLifecycleSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        )
        .await
        .expect_err("closed pending credential replacement must not replay");

    assert!(matches!(
        replay_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingCredentialLifecycleActionNotExecutable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_credential_removal_is_core_owned() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("pending-removal-subject");
    let target_credential_id = id("pending-removal-totp-credential");
    let pending_action_id = id("pending-removal-action");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::SharedSecretOtpVerifier,
                "totp_app",
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Remove,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending removal action")],
        )
        .await
        .expect("seed pending removal action");

    let execution = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: None,
                subject_auth_revocation:
                    CredentialLifecycleSubjectAuthRevocation::PreserveExistingAuthState,
            },
        )
        .await
        .expect("execute mature pending credential removal");

    assert_eq!(
        execution.outcome(),
        &Outcome::NonResetPendingCredentialLifecycleActionExecuted(
            NonResetPendingCredentialLifecycleActionExecutionOutcome {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Remove,
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Revoked,
        "removal execution must revoke the target credential metadata"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Remove,
        )
        .await,
        0,
        "removal execution must close the pending action"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_credential_replacement_cancellation_closes_open_action()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("pending-replacement-cancel-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "pending-replacement-cancel-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("pending-replacement-cancel-credential");
    let pending_action_id = id("pending-replacement-cancel-action");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Replace,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending replacement action")],
        )
        .await
        .expect("seed pending replacement action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let execution = runtime
        .execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialLifecycleActionInput {
                now: at(80),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("cancel pending credential replacement");

    assert_eq!(
        execution.outcome(),
        &Outcome::NonResetPendingCredentialLifecycleActionCancelled(
            NonResetPendingCredentialLifecycleActionCancellationOutcome {
                subject_id,
                target_credential_instance_id: target_credential_id,
                action: CredentialLifecycleAction::Replace,
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Replace,
        )
        .await,
        0,
        "cancellation must close the pending replacement action"
    );

    let replay_error = runtime
        .execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialLifecycleActionInput {
                now: at(90),
                pending_action_id,
            },
        )
        .await
        .expect_err("closed pending credential replacement cancellation must not replay");

    assert!(matches!(
        replay_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingCredentialLifecycleActionNotCancellable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_subject_auth_state_deletion_closes_action_and_revokes_auth_state()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("pending-subject-deletion-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "pending-subject-deletion-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let pending_action_id = id("pending-subject-deletion-action");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[PendingSubjectLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                SubjectLifecycleAction::DeleteSubjectAuthState,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending subject auth-state deletion action")],
        )
        .await
        .expect("seed pending subject auth-state deletion action");

    let execution = runtime
        .execute_mature_pending_subject_auth_state_deletion_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingSubjectAuthStateDeletionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("execute mature pending subject auth-state deletion");

    assert_eq!(
        execution.outcome(),
        &Outcome::PendingSubjectAuthStateDeletionExecuted(
            PendingSubjectAuthStateDeletionExecutionOutcome {
                subject_id: subject_id.clone(),
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        0,
        "execution must close the pending subject auth-state deletion action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "execution must commit the subject auth-state deletion security notice"
    );

    let resolved_after_deletion = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]),
            ResolveRequestInput {
                now: at(260),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve original session after subject auth-state deletion");
    assert_eq!(
        resolved_after_deletion.outcome(),
        &Outcome::NeedsFullAuthentication,
        "subject auth-state deletion must invalidate sessions created before the deletion cutoff"
    );

    let replay_error = runtime
        .execute_mature_pending_subject_auth_state_deletion_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingSubjectAuthStateDeletionInput {
                now: at(260),
                pending_action_id,
            },
        )
        .await
        .expect_err("closed pending subject auth-state deletion must not replay");

    assert!(matches!(
        replay_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingSubjectLifecycleActionNotExecutable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_subject_auth_state_deletion_cancellation_closes_open_action()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("pending-subject-deletion-cancel-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "pending-subject-deletion-cancel-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let pending_action_id = id("pending-subject-deletion-cancel-action");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[PendingSubjectLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                SubjectLifecycleAction::DeleteSubjectAuthState,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending subject auth-state deletion action")],
        )
        .await
        .expect("seed pending subject auth-state deletion action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let cancellation = runtime
        .execute_authenticated_pending_subject_auth_state_deletion_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("cancel pending subject auth-state deletion");

    assert_eq!(
        cancellation.outcome(),
        &Outcome::PendingSubjectAuthStateDeletionCancelled(
            PendingSubjectAuthStateDeletionCancellationOutcome {
                subject_id: subject_id.clone(),
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        0,
        "cancellation must close the pending subject auth-state deletion action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "cancellation must commit the subject auth-state deletion cancellation notice"
    );

    let replay_error = runtime
        .execute_authenticated_pending_subject_auth_state_deletion_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
                now: at(100),
                pending_action_id,
            },
        )
        .await
        .expect_err("closed pending subject auth-state deletion cancellation must not replay");

    assert!(matches!(
        replay_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingSubjectLifecycleActionNotCancellable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_subject_auth_state_deletion_cancellation_rejects_wrong_subject_session() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let pending_subject_id = id("pending-subject-deletion-owner");
    let session_subject_id = id("pending-subject-deletion-other-session");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "pending-subject-deletion-wrong-session-bootstrap",
        20,
        session_subject_id,
        false,
    )
    .await;
    let pending_action_id = id("pending-subject-deletion-wrong-session-action");
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[PendingSubjectLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                pending_subject_id,
                SubjectLifecycleAction::DeleteSubjectAuthState,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending subject auth-state deletion action")],
        )
        .await
        .expect("seed pending subject auth-state deletion action");

    let cancellation_error = runtime
        .execute_authenticated_pending_subject_auth_state_deletion_cancellation_from_headers(
            &headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]),
            CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect_err("wrong subject session must not cancel pending subject auth-state deletion");

    assert!(matches!(
        cancellation_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleActionNotAuthorized
        )
    ));
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        1,
        "wrong-subject cancellation must leave the pending subject auth-state deletion action open"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_out_of_band_completion_without_challenge_runtime() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;

    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &HeaderMap::new(),
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: ActiveProofMethodResponsePayload::try_from_bytes(
                    b"out-of-band-response".as_slice(),
                )
                .expect("out-of-band response payload"),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("active-proof method completion must use a challenge cookie");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::MissingActiveProofChallengeCookie
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_executes_email_otp_method_lifecycle_when_database_is_available() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = harness
        .email_otp_plugin
        .as_ref()
        .expect("email otp method plugin");
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("email-otp-method-subject");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("email-otp-method:recipient-hash:window"),
                recipient_handle: recipient_handle_for_test_subject(
                    "email-otp-method",
                    &subject_id,
                ),
                idempotency_key: "email-otp-method-delivery-1".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue email otp challenge");
    let (attempt_id, challenge_id) = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            ..
        } => (attempt_id.clone(), challenge_id.clone()),
        outcome => panic!("expected email otp challenge issue, got {outcome:?}"),
    };
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(pool, store_config, &challenge_id).await,
        1
    );
    assert_eq!(
        email_otp
            .count_open_method_challenges_for_test(pool)
            .await
            .expect("count open email otp challenges"),
        1
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email otp delivery commands"),
        1
    );

    let resend_request = email_otp
        .resend_challenge_request(EmailOtpResendChallenge {
            now: at(40),
            delivery_idempotency_key: "email-otp-method-delivery-2".to_owned(),
        })
        .expect("build email otp resend request");
    let resend_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let resent = runtime
        .execute_out_of_band_challenge_resend_from_headers(&resend_headers, resend_request)
        .await
        .expect("resend email otp challenge");
    assert!(matches!(
        resent.outcome(),
        Outcome::OutOfBandChallengeResent {
            resend_count: 1,
            ..
        }
    ));
    assert_eq!(
        fetch_out_of_band_challenge_resend_count(pool, store_config, &challenge_id).await,
        1
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(pool, store_config, &challenge_id).await,
        2
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email otp delivery commands after resend"),
        2
    );

    harness.database_operation_observer.clear();
    let wrong_response = email_otp
        .complete_challenge_response(EmailOtpCompleteChallengeResponse {
            now: at(45),
            secret_response: ActiveProofChallengeResponseSecret::try_from(
                b"wrong-email-otp-code".as_slice(),
            )
            .expect("wrong email otp response secret"),
            weak_proof_gate_response: None,
        })
        .expect("build wrong email otp response completion");
    let wrong_completion_error = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]),
            wrong_response,
        )
        .await
        .expect_err("wrong email otp code must reject before state load");
    assert!(matches!(
        wrong_completion_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::StatelessFastFailVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "wrong email otp code must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1,
        "wrong email otp code must leave the authoritative challenge open"
    );
    assert_eq!(
        email_otp
            .count_open_method_challenges_for_test(pool)
            .await
            .expect("count open email otp challenges after wrong code"),
        1,
        "wrong email otp code must not consume method-owned challenge state"
    );

    let response = email_otp
        .complete_challenge_response(EmailOtpCompleteChallengeResponse {
            now: at(50),
            secret_response: response_secret,
            weak_proof_gate_response: None,
        })
        .expect("build email otp response completion");
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(&completion_headers, response)
        .await
        .expect("complete email otp challenge");
    assert!(matches!(
        completed.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    assert!(set_cookie_headers_contain_deletion(
        completed.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge="
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );
    assert_eq!(
        email_otp
            .count_open_method_challenges_for_test(pool)
            .await
            .expect("count open email otp challenges after completion"),
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_derives_email_otp_subject_from_method_state() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let recipient_handle = "subject-resolving-email-otp-recipient";
    let subject_id: SubjectId = id("subject-resolved-by-email-otp-plugin");
    let source_id: VerifiedProofSourceId = id("verified-email-identifier-binding");
    let subject_resolver = Arc::new(StaticEmailOtpSubjectResolver::new(
        recipient_handle,
        subject_id.clone(),
        source_id.clone(),
    ));
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_subject_resolver(
        subject_resolver.clone(),
    )
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = harness
        .email_otp_plugin
        .as_ref()
        .expect("email otp method plugin");
    let empty_headers = HeaderMap::new();
    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("subject-resolving-email-otp:window"),
                recipient_handle: recipient_handle.to_owned(),
                idempotency_key: "subject-resolving-email-otp-delivery".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue email otp challenge");
    let (attempt_id, challenge_id) = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            ..
        } => (attempt_id.clone(), challenge_id.clone()),
        outcome => panic!("expected email otp challenge issue, got {outcome:?}"),
    };
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();

    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]),
            email_otp
                .complete_challenge_response(EmailOtpCompleteChallengeResponse {
                    now: at(40),
                    secret_response: response_secret,
                    weak_proof_gate_response: None,
                })
                .expect("build email otp response"),
        )
        .await
        .expect("complete email otp challenge");
    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        }
    );
    assert_eq!(
        fetch_active_proof_attempt_subject_id(pool, store_config, &attempt_id).await,
        Some(subject_id),
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::OutOfBandIdentifier,
            source_id,
        )),
    );
    assert_eq!(subject_resolver.call_count(), 1);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_bad_email_otp_before_subject_resolution() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let recipient_handle = "bad-email-otp-fast-fail-recipient";
    let subject_resolver = Arc::new(StaticEmailOtpSubjectResolver::new(
        recipient_handle,
        id("bad-email-otp-fast-fail-subject"),
        id("bad-email-otp-fast-fail-source"),
    ));
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_subject_resolver(
        subject_resolver.clone(),
    )
    .await;
    let runtime = &harness.runtime;
    let email_otp = harness
        .email_otp_plugin
        .as_ref()
        .expect("email otp method plugin");
    let empty_headers = HeaderMap::new();
    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("bad-email-otp-fast-fail:window"),
                recipient_handle: recipient_handle.to_owned(),
                idempotency_key: "bad-email-otp-fast-fail-delivery".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue email otp challenge");
    assert!(matches!(
        issued.outcome(),
        Outcome::OutOfBandChallengeIssued { .. }
    ));
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let wrong_response_secret = ActiveProofChallengeResponseSecret::try_from(b"wrong".as_slice())
        .expect("wrong challenge response secret");

    let error = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]),
            email_otp
                .complete_challenge_response(EmailOtpCompleteChallengeResponse {
                    now: at(40),
                    secret_response: wrong_response_secret,
                    weak_proof_gate_response: None,
                })
                .expect("build email otp response"),
        )
        .await
        .expect_err("bad OTP must fail before subject resolution");

    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::StatelessFastFailVerificationFailed
        )
    ));
    assert_eq!(subject_resolver.call_count(), 0);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_executes_session_and_trusted_device_lifecycle_when_database_is_available()
{
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("login:email-hash:window"),
                recipient_handle: recipient_handle_for_test_subject("login", &id("subject")),
                idempotency_key: "mail-idempotency-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue challenge through Postgres runtime");
    let (attempt_id, challenge_id) = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id: issued_attempt_id,
            challenge_id,
            expires_at,
        } => {
            assert_eq!(expires_at, &at(60));
            (issued_attempt_id.clone(), challenge_id.clone())
        }
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(issued.set_cookie_headers())
            .to_owned();
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let mut challenge_headers = HeaderMap::new();
    challenge_headers.insert(
        COOKIE,
        HeaderValue::from_str(challenge_cookie_pair).expect("cookie header"),
    );

    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &challenge_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(40),
                secret_response: response_secret,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete challenge through Postgres runtime");
    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        }
    );
    assert_eq!(completed.set_cookie_headers().as_slice().len(), 1);

    let satisfied_proof_count =
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await;
    assert_eq!(satisfied_proof_count, 1);
    let open_challenge_count = count_open_challenges(pool, store_config).await;
    assert_eq!(open_challenge_count, 0);

    let full_authentication = runtime
        .execute_full_authentication_completion_from_headers(
            &continuation_headers,
            CompleteFullAuthenticationInput {
                now: at(45),
                trust_device: Some(TrustDeviceAfterFullAuthenticationInput {
                    display_label: Some("test browser".to_owned()),
                }),
            },
        )
        .await
        .expect("complete full authentication through Postgres runtime");
    let session_id = match full_authentication.outcome() {
        Outcome::Authenticated(authenticated) => {
            assert_eq!(authenticated.subject_id, id("subject"));
            assert_eq!(
                authenticated.source,
                AuthenticationSource::FullAuthentication
            );
            assert!(authenticated.step_up_is_fresh);
            authenticated.session_id.clone()
        }
        outcome => panic!("expected full authentication, got {outcome:?}"),
    };
    let device_id = fetch_trusted_device_id_by_display_label(pool, store_config, "test browser")
        .await
        .expect("trusted device id");
    let session_cookie_pair = cookie_pair_from_set_cookie(
        full_authentication.set_cookie_headers(),
        "__Host-__paranoid_auth_session=",
    );
    let trusted_device_cookie_pair = cookie_pair_from_set_cookie(
        full_authentication.set_cookie_headers(),
        "__Host-__paranoid_auth_trusted_device=",
    );
    assert_eq!(count_all_sessions(pool, store_config).await, 1);
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &session_id).await,
        1
    );
    assert_eq!(count_all_trusted_devices(pool, store_config).await, 1);
    assert_eq!(
        count_trusted_device_secret_macs_for_device(pool, store_config, &device_id).await,
        1
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &attempt_id).await,
        0,
        "full authentication must close and delete the active-proof attempt"
    );

    let mut session_headers = HeaderMap::new();
    session_headers.insert(
        COOKIE,
        HeaderValue::from_str(session_cookie_pair).expect("session cookie header"),
    );
    let resolved = runtime
        .execute_request_resolution_from_headers(
            &session_headers,
            ResolveRequestInput {
                now: at(50),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve issued session through Postgres runtime");
    assert_eq!(
        resolved.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: id("subject"),
            session_id: session_id.clone(),
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: true,
        })
    );
    assert!(
        resolved
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_session=")),
        "authoritative request resolution should reissue a safe-read-capable session cookie"
    );
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &session_id).await,
        1,
        "non-refresh request resolution must reuse the presented session secret without creating another MAC row"
    );

    let mut trusted_device_headers = HeaderMap::new();
    trusted_device_headers.insert(
        COOKIE,
        HeaderValue::from_str(trusted_device_cookie_pair).expect("trusted-device cookie header"),
    );
    let revived = runtime
        .execute_request_resolution_from_headers(
            &trusted_device_headers,
            ResolveRequestInput {
                now: at(60),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("silently revive session from trusted-device cookie through Postgres runtime");
    let revived_session_id = match revived.outcome() {
        Outcome::Authenticated(authenticated) => {
            assert_eq!(authenticated.subject_id, id("subject"));
            assert_eq!(
                authenticated.source,
                AuthenticationSource::SilentTrustedDeviceRevival
            );
            assert!(!authenticated.step_up_is_fresh);
            authenticated.session_id.clone()
        }
        outcome => panic!("expected silent trusted-device revival, got {outcome:?}"),
    };
    assert!(
        revived
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_session=")),
        "trusted-device silent revival must issue a fresh session cookie"
    );
    assert!(
        revived
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_trusted_device=")),
        "trusted-device silent revival must rotate and reissue the trusted-device cookie"
    );
    assert_eq!(count_all_sessions(pool, store_config).await, 2);
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &revived_session_id).await,
        1
    );
    assert_eq!(
        count_trusted_device_secret_macs_for_device(pool, store_config, &device_id).await,
        2
    );
    assert_eq!(
        fetch_trusted_device_current_secret_version(pool, store_config, &device_id).await,
        2
    );

    let rotated_trusted_device_cookie_pair = cookie_pair_from_set_cookie(
        revived.set_cookie_headers(),
        "__Host-__paranoid_auth_trusted_device=",
    );
    let mut rotated_trusted_device_headers = HeaderMap::new();
    rotated_trusted_device_headers.insert(
        COOKIE,
        HeaderValue::from_str(rotated_trusted_device_cookie_pair)
            .expect("rotated trusted-device cookie header"),
    );
    let needs_active_proof = runtime
        .execute_request_resolution_from_headers(
            &rotated_trusted_device_headers,
            ResolveRequestInput {
                now: at(600),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve trusted-device cookie after silent revival window");
    assert_eq!(
        needs_active_proof.outcome(),
        &Outcome::NeedsActiveProofFromTrustedDevice {
            device_credential_id: device_id.clone(),
            subject_id: id("subject"),
        }
    );
    assert!(needs_active_proof.set_cookie_headers().is_empty());

    let active_revival_attempt = runtime
        .execute_current_trusted_device_active_proof_attempt_start_from_headers(
            &rotated_trusted_device_headers,
            StartCurrentTrustedDeviceActiveProofAttemptInput {
                now: at(610),
                proof_use: ProofUse::ReviveTrustedDeviceWithActiveProof,
            },
        )
        .await
        .expect("start trusted-device active-proof revival attempt through Postgres runtime");
    let revival_attempt_id = match active_revival_attempt.outcome() {
        Outcome::ActiveProofAttemptStarted {
            attempt_id,
            expires_at,
        } => {
            assert_eq!(expires_at, &at(730));
            attempt_id.clone()
        }
        outcome => panic!("expected revival active proof attempt start, got {outcome:?}"),
    };
    let revival_continuation_cookie_pair = active_proof_continuation_cookie_pair_from_set_cookie(
        active_revival_attempt.set_cookie_headers(),
    )
    .to_owned();
    let revival_continuation_headers =
        headers_from_cookie_pairs(&[revival_continuation_cookie_pair.as_str()]);

    let active_revival_challenge = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &revival_continuation_headers,
            IssueOutOfBandChallengeInput {
                now: at(620),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("active-revival method declaration"),
                challenge_dedupe_key: dedupe_key("revival:email-hash:window"),
                recipient_handle: "opaque-email-handle".to_owned(),
                idempotency_key: "revival-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect("issue trusted-device active-revival challenge through Postgres runtime");
    let revival_challenge_id = match active_revival_challenge.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            expires_at,
        } => {
            assert_eq!(attempt_id, &revival_attempt_id);
            assert_eq!(expires_at, &at(660));
            challenge_id.clone()
        }
        outcome => panic!("expected active-revival challenge issue, got {outcome:?}"),
    };
    let active_revival_response_secret = email_otp
        .fetch_response_secret_for_test(pool, &revival_challenge_id)
        .await
        .expect("fetch generated active-revival email otp response secret");
    let active_revival_challenge_cookie_pair = cookie_pair_from_set_cookie(
        active_revival_challenge.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let mut active_revival_challenge_headers = HeaderMap::new();
    active_revival_challenge_headers.insert(
        COOKIE,
        HeaderValue::from_str(active_revival_challenge_cookie_pair)
            .expect("active-revival challenge cookie header"),
    );

    let active_revival_proof = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &active_revival_challenge_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(630),
                secret_response: active_revival_response_secret,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete trusted-device active-revival proof through Postgres runtime");
    assert_eq!(
        active_revival_proof.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: revival_attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        }
    );

    let active_revival = runtime
        .execute_trusted_device_revival_completion_from_headers(
            &headers_from_cookie_pairs(&[
                rotated_trusted_device_cookie_pair,
                revival_continuation_cookie_pair.as_str(),
            ]),
            CompleteTrustedDeviceRevivalWithActiveProofInput { now: at(640) },
        )
        .await
        .expect("complete trusted-device active-proof revival through Postgres runtime");
    let active_revival_session_id = match active_revival.outcome() {
        Outcome::Authenticated(authenticated) => {
            assert_eq!(authenticated.subject_id, id("subject"));
            assert_eq!(
                authenticated.source,
                AuthenticationSource::TrustedDeviceRevivalWithActiveProof
            );
            assert!(authenticated.step_up_is_fresh);
            authenticated.session_id.clone()
        }
        outcome => panic!("expected active trusted-device revival, got {outcome:?}"),
    };
    assert!(
        active_revival
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_session=")),
        "trusted-device active-proof revival must issue a fresh session cookie"
    );
    assert!(
        active_revival
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_trusted_device=")),
        "trusted-device active-proof revival must rotate and reissue the trusted-device cookie"
    );
    assert_eq!(count_all_sessions(pool, store_config).await, 3);
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &active_revival_session_id).await,
        1
    );
    assert_eq!(
        count_trusted_device_secret_macs_for_device(pool, store_config, &device_id).await,
        3
    );
    assert_eq!(
        fetch_trusted_device_current_secret_version(pool, store_config, &device_id).await,
        3
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &revival_attempt_id).await,
        0,
        "trusted-device active-proof revival must close and delete the revival attempt"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_tripwires_replayed_previous_secrets_after_grace() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;

    let session_tripwire_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "session-tripwire",
        20,
        id("session-tripwire-subject"),
        true,
    )
    .await;
    let session_tripwire_device_id = session_tripwire_state
        .trusted_device_credential_id
        .clone()
        .expect("session-tripwire trusted device id");
    let original_session_cookie_pair = session_tripwire_state.session_cookie_pair.as_str();
    let original_trusted_device_cookie_pair = session_tripwire_state
        .trusted_device_cookie_pair
        .as_deref()
        .expect("session-tripwire trusted-device cookie");

    let refreshed = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[original_session_cookie_pair]),
            ResolveRequestInput {
                now: at(130),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("refresh session before session tripwire replay");
    assert!(matches!(
        refreshed.outcome(),
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::RefreshedSession,
            ..
        })
    ));
    assert_eq!(
        count_session_secret_macs_for_session(
            pool,
            store_config,
            &session_tripwire_state.session_id
        )
        .await,
        2,
        "session refresh must leave one current and one previous secret MAC"
    );

    let replayed_old_session = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[
                original_session_cookie_pair,
                original_trusted_device_cookie_pair,
            ]),
            ResolveRequestInput {
                now: at(136),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("replay old session cookie after grace through Postgres runtime");
    assert_eq!(
        replayed_old_session.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            replayed_old_session.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "session tripwire must delete the presented session cookie"
    );
    assert!(
        set_cookie_headers_contain_deletion(
            replayed_old_session.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "session tripwire must delete the associated trusted-device cookie"
    );
    assert_eq!(
        fetch_session_revoked_at(pool, store_config, &session_tripwire_state.session_id).await,
        Some(136)
    );
    assert_eq!(
        fetch_trusted_device_revoked_at(pool, store_config, &session_tripwire_device_id).await,
        Some(136)
    );

    let trusted_device_tripwire_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "trusted-device-tripwire",
        180,
        id("trusted-device-tripwire-subject"),
        true,
    )
    .await;
    let trusted_device_tripwire_device_id = trusted_device_tripwire_state
        .trusted_device_credential_id
        .clone()
        .expect("trusted-device-tripwire trusted device id");
    let original_device_cookie_pair = trusted_device_tripwire_state
        .trusted_device_cookie_pair
        .as_deref()
        .expect("trusted-device-tripwire trusted-device cookie");

    let revived_from_device = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[original_device_cookie_pair]),
            ResolveRequestInput {
                now: at(220),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("silently revive from trusted-device before device tripwire replay");
    assert!(matches!(
        revived_from_device.outcome(),
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SilentTrustedDeviceRevival,
            ..
        })
    ));
    assert_eq!(
        count_trusted_device_secret_macs_for_device(
            pool,
            store_config,
            &trusted_device_tripwire_device_id
        )
        .await,
        2,
        "trusted-device rotation must leave one current and one previous secret MAC"
    );
    let session_count_before_device_tripwire = count_all_sessions(pool, store_config).await;

    let replayed_old_device = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[original_device_cookie_pair]),
            ResolveRequestInput {
                now: at(226),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("replay old trusted-device cookie after grace through Postgres runtime");
    assert_eq!(
        replayed_old_device.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            replayed_old_device.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "trusted-device tripwire must delete the presented trusted-device cookie"
    );
    assert_eq!(
        fetch_trusted_device_revoked_at(pool, store_config, &trusted_device_tripwire_device_id)
            .await,
        Some(226)
    );
    assert_eq!(
        count_all_sessions(pool, store_config).await,
        session_count_before_device_tripwire,
        "trusted-device tripwire must not create a replacement session"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_executes_step_up_completion_when_database_is_available() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("step-up-postgres-subject");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "step-up-postgres",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let session_headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let sensitive_before_step_up = runtime
        .execute_request_resolution_from_headers(
            &session_headers,
            ResolveRequestInput {
                now: at(80),
                request_kind: RequestKind::Sensitive,
            },
        )
        .await
        .expect("sensitive request should resolve through Postgres runtime");
    assert_eq!(
        sensitive_before_step_up.outcome(),
        &Outcome::NeedsStepUp {
            session_id: issued_auth.session_id.clone(),
            subject_id: subject_id.clone(),
        }
    );

    let started_step_up = runtime
        .execute_current_session_active_proof_attempt_start_from_headers(
            &session_headers,
            StartCurrentSessionActiveProofAttemptInput {
                now: at(85),
                proof_use: ProofUse::SatisfyStepUp,
            },
        )
        .await
        .expect("start step-up active proof attempt through Postgres runtime");
    let step_up_attempt_id = match started_step_up.outcome() {
        Outcome::ActiveProofAttemptStarted { attempt_id, .. } => attempt_id.clone(),
        outcome => panic!("expected active proof attempt start, got {outcome:?}"),
    };
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(started_step_up.set_cookie_headers())
            .to_owned();
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    let issued_challenge = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &continuation_headers,
            IssueOutOfBandChallengeInput {
                now: at(90),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("step-up method declaration"),
                challenge_dedupe_key: dedupe_key("step-up-postgres:email-hash:window"),
                recipient_handle: "step-up-postgres-opaque-email-handle".to_owned(),
                idempotency_key: "step-up-postgres-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect("issue step-up challenge through Postgres runtime");
    let step_up_challenge_id = match issued_challenge.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            ..
        } => {
            assert_eq!(attempt_id, &step_up_attempt_id);
            challenge_id.clone()
        }
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    let step_up_response_secret = email_otp
        .fetch_response_secret_for_test(pool, &step_up_challenge_id)
        .await
        .expect("fetch generated step-up email otp response secret");
    let step_up_challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued_challenge.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let step_up_challenge_headers = headers_from_cookie_pairs(&[step_up_challenge_cookie_pair]);
    let completed_step_up_proof = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &step_up_challenge_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(95),
                secret_response: step_up_response_secret,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete step-up challenge through Postgres runtime");
    assert_eq!(
        completed_step_up_proof.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: step_up_attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        }
    );

    let step_up_headers = headers_from_cookie_pairs(&[
        issued_auth.session_cookie_pair.as_str(),
        continuation_cookie_pair.as_str(),
    ]);
    let step_up = runtime
        .execute_step_up_completion_from_headers(
            &step_up_headers,
            CompleteStepUpInput { now: at(100) },
        )
        .await
        .expect("complete step-up through Postgres runtime");
    assert_eq!(
        step_up.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: subject_id.clone(),
            session_id: issued_auth.session_id.clone(),
            source: AuthenticationSource::StepUp,
            step_up_is_fresh: true,
        })
    );
    assert!(
        step_up
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_session=")),
        "step-up must rotate and reissue the session cookie"
    );
    assert!(
        set_cookie_headers_contain_deletion(
            step_up.set_cookie_headers(),
            "__Host-__paranoid_auth_active_proof_continuation="
        ),
        "step-up must clear the active-proof continuation cookie"
    );
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &issued_auth.session_id).await,
        2,
        "step-up must store the newly rotated session secret MAC"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &step_up_attempt_id).await,
        0,
        "step-up must close and delete the active-proof attempt"
    );

    let stepped_up_session_cookie_pair = cookie_pair_from_set_cookie(
        step_up.set_cookie_headers(),
        "__Host-__paranoid_auth_session=",
    );
    let sensitive_after_step_up = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[stepped_up_session_cookie_pair]),
            ResolveRequestInput {
                now: at(105),
                request_kind: RequestKind::Sensitive,
            },
        )
        .await
        .expect("resolve sensitive request after step-up through Postgres runtime");
    assert_eq!(
        sensitive_after_step_up.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id,
            session_id: issued_auth.session_id,
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: true,
        })
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_executes_revocation_paths_when_database_is_available() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;

    let logout_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "logout",
        20,
        id("subject"),
        false,
    )
    .await;
    let logout_headers = headers_from_cookie_pairs(&[logout_state.session_cookie_pair.as_str()]);
    let logout = runtime
        .execute_from_headers(
            &logout_headers,
            Command::LogoutCurrentSession(LogoutCurrentSession { now: at(50) }),
        )
        .await
        .expect("logout current session through Postgres runtime");
    assert_eq!(
        logout.outcome(),
        &Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(id("subject")),
            target: RevocationTarget::CurrentSession,
        })
    );
    assert!(
        set_cookie_headers_contain_deletion(
            logout.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "logout must delete the current session cookie"
    );
    let stale_logged_out_session = runtime
        .execute_request_resolution_from_headers(
            &logout_headers,
            ResolveRequestInput {
                now: at(55),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve logged-out session through Postgres runtime");
    assert_eq!(
        stale_logged_out_session.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            stale_logged_out_session.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "stale logged-out session cookie must be cleared"
    );

    let targeted_session_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "targeted-session",
        60,
        id("subject"),
        false,
    )
    .await;
    let targeted_session_revocation = runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RevokeSession(RevokeSession {
                now: at(90),
                subject_id: id("subject"),
                session_id: targeted_session_state.session_id.clone(),
                reason: RevocationReason::RemoteRevocation,
            }),
        )
        .await
        .expect("targeted session revocation through Postgres runtime");
    assert_eq!(
        targeted_session_revocation.outcome(),
        &Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(id("subject")),
            target: RevocationTarget::Session(targeted_session_state.session_id.clone()),
        })
    );
    let targeted_session_headers =
        headers_from_cookie_pairs(&[targeted_session_state.session_cookie_pair.as_str()]);
    let stale_targeted_session = runtime
        .execute_request_resolution_from_headers(
            &targeted_session_headers,
            ResolveRequestInput {
                now: at(95),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve targeted-revoked session through Postgres runtime");
    assert_eq!(
        stale_targeted_session.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            stale_targeted_session.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "targeted-revoked session cookie must be cleared on reuse"
    );

    let targeted_device_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "targeted-device",
        100,
        id("subject"),
        true,
    )
    .await;
    let targeted_device_cookie_pair = targeted_device_state
        .trusted_device_cookie_pair
        .as_deref()
        .expect("trusted-device cookie");
    let targeted_device_headers = headers_from_cookie_pairs(&[targeted_device_cookie_pair]);
    let targeted_device_revocation = runtime
        .execute_from_headers(
            &targeted_device_headers,
            Command::RevokeTrustedDevice(RevokeTrustedDevice {
                now: at(130),
                subject_id: id("subject"),
                device_credential_id: targeted_device_state
                    .trusted_device_credential_id
                    .clone()
                    .expect("targeted device id"),
                reason: RevocationReason::RemoteRevocation,
            }),
        )
        .await
        .expect("targeted trusted-device revocation through Postgres runtime");
    assert_eq!(
        targeted_device_revocation.outcome(),
        &Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(id("subject")),
            target: RevocationTarget::TrustedDevice(
                targeted_device_state
                    .trusted_device_credential_id
                    .clone()
                    .expect("targeted device id"),
            ),
        })
    );
    assert!(
        set_cookie_headers_contain_deletion(
            targeted_device_revocation.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "targeted trusted-device revocation must delete the presented device cookie"
    );
    let stale_targeted_device = runtime
        .execute_request_resolution_from_headers(
            &targeted_device_headers,
            ResolveRequestInput {
                now: at(135),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve targeted-revoked trusted device through Postgres runtime");
    assert_eq!(
        stale_targeted_device.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            stale_targeted_device.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "targeted-revoked trusted-device cookie must be cleared on reuse"
    );

    let subject_wide_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "subject-wide",
        140,
        id("subject"),
        true,
    )
    .await;
    let subject_wide_device_cookie_pair = subject_wide_state
        .trusted_device_cookie_pair
        .as_deref()
        .expect("subject-wide trusted-device cookie");
    let subject_wide_headers = headers_from_cookie_pairs(&[
        subject_wide_state.session_cookie_pair.as_str(),
        subject_wide_device_cookie_pair,
    ]);
    let subject_wide_revocation = runtime
        .execute_from_headers(
            &subject_wide_headers,
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(170),
                subject_id: id("subject"),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("subject-wide revocation through Postgres runtime");
    assert_eq!(
        subject_wide_revocation.outcome(),
        &Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(id("subject")),
            target: RevocationTarget::SubjectAuthState(id("subject")),
        })
    );
    assert!(
        set_cookie_headers_contain_deletion(
            subject_wide_revocation.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "subject-wide revocation must delete the presented session cookie"
    );
    assert!(
        set_cookie_headers_contain_deletion(
            subject_wide_revocation.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "subject-wide revocation must delete the presented trusted-device cookie"
    );
    let stale_subject_wide_session_headers =
        headers_from_cookie_pairs(&[subject_wide_state.session_cookie_pair.as_str()]);
    let stale_subject_wide_session = runtime
        .execute_request_resolution_from_headers(
            &stale_subject_wide_session_headers,
            ResolveRequestInput {
                now: at(175),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve subject-wide-revoked session through Postgres runtime");
    assert_eq!(
        stale_subject_wide_session.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    let stale_subject_wide_device_headers =
        headers_from_cookie_pairs(&[subject_wide_device_cookie_pair]);
    let stale_subject_wide_device = runtime
        .execute_request_resolution_from_headers(
            &stale_subject_wide_device_headers,
            ResolveRequestInput {
                now: at(175),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve subject-wide-revoked trusted device through Postgres runtime");
    assert_eq!(
        stale_subject_wide_device.outcome(),
        &Outcome::NeedsFullAuthentication
    );

    assert_eq!(
        fetch_session_revoked_at(pool, store_config, &logout_state.session_id).await,
        Some(50)
    );
    assert_eq!(
        fetch_session_revoked_at(pool, store_config, &targeted_session_state.session_id).await,
        Some(90)
    );
    assert_eq!(
        fetch_trusted_device_revoked_at(
            pool,
            store_config,
            &targeted_device_state
                .trusted_device_credential_id
                .clone()
                .expect("targeted device id"),
        )
        .await,
        Some(130)
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &id("subject")).await,
        Some(170)
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_stale_loaded_state_commits_after_revocation_when_database_is_available()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let store = postgres_runtime_test_store(store_config);

    let logout_race_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "logout-race",
        20,
        id("subject"),
        false,
    )
    .await;
    let logout_race_headers =
        headers_from_cookie_pairs(&[logout_race_state.session_cookie_pair.as_str()]);
    let mut stale_logout_refresh_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale logout-refresh transaction");
    let stale_logout_refresh_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_logout_refresh_tx,
        &store,
        &logout_race_headers,
        Command::ResolveRequest(ResolveRequest {
            now: at(130),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
    )
    .await;
    assert_eq!(
        stale_logout_refresh_plan.planned.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: id("subject"),
            session_id: logout_race_state.session_id.clone(),
            source: AuthenticationSource::RefreshedSession,
            step_up_is_fresh: false,
        })
    );
    runtime
        .execute_from_headers(
            &logout_race_headers,
            Command::LogoutCurrentSession(LogoutCurrentSession { now: at(131) }),
        )
        .await
        .expect("commit logout racing stale session refresh");
    let logout_refresh_error =
        commit_planned_work_in_current_transaction_expect_precondition_error(
            &mut stale_logout_refresh_tx,
            &store,
            &stale_logout_refresh_plan,
        )
        .await;
    assert_precondition_failed(
        &logout_refresh_error,
        "session no longer matches loaded state",
    );
    stale_logout_refresh_tx
        .rollback()
        .await
        .expect("roll back failed stale logout-refresh transaction");
    assert_eq!(
        fetch_session_revoked_at(pool, store_config, &logout_race_state.session_id).await,
        Some(131)
    );
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &logout_race_state.session_id)
            .await,
        1,
        "failed stale refresh must not insert a replacement session secret MAC"
    );

    let subject_race_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "subject-race",
        140,
        id("subject"),
        false,
    )
    .await;
    let subject_race_headers =
        headers_from_cookie_pairs(&[subject_race_state.session_cookie_pair.as_str()]);
    let mut stale_subject_refresh_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale subject-refresh transaction");
    let stale_subject_refresh_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_subject_refresh_tx,
        &store,
        &subject_race_headers,
        Command::ResolveRequest(ResolveRequest {
            now: at(250),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
    )
    .await;
    assert_eq!(
        stale_subject_refresh_plan.planned.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: id("subject"),
            session_id: subject_race_state.session_id.clone(),
            source: AuthenticationSource::RefreshedSession,
            step_up_is_fresh: false,
        })
    );
    runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(251),
                subject_id: id("subject"),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("commit subject-wide revocation racing stale session refresh");
    let subject_refresh_error =
        commit_planned_work_in_current_transaction_expect_precondition_error(
            &mut stale_subject_refresh_tx,
            &store,
            &stale_subject_refresh_plan,
        )
        .await;
    assert_precondition_failed(
        &subject_refresh_error,
        "subject auth state invalidates target",
    );
    stale_subject_refresh_tx
        .rollback()
        .await
        .expect("roll back failed stale subject-refresh transaction");
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &id("subject")).await,
        Some(251)
    );
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &subject_race_state.session_id)
            .await,
        1,
        "failed stale subject-revoked refresh must not insert a replacement session secret MAC"
    );

    let device_race_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "device-race",
        300,
        id("device-race-subject"),
        true,
    )
    .await;
    let device_race_cookie_pair = device_race_state
        .trusted_device_cookie_pair
        .as_deref()
        .expect("device-race trusted-device cookie");
    let device_race_headers = headers_from_cookie_pairs(&[device_race_cookie_pair]);
    let mut stale_device_rotation_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale device-rotation transaction");
    let stale_device_rotation_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_device_rotation_tx,
        &store,
        &device_race_headers,
        Command::ResolveRequest(ResolveRequest {
            now: at(360),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("device-race-stale-revival-session")),
        }),
    )
    .await;
    assert_eq!(
        stale_device_rotation_plan.planned.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: id("device-race-subject"),
            session_id: id("device-race-stale-revival-session"),
            source: AuthenticationSource::SilentTrustedDeviceRevival,
            step_up_is_fresh: false,
        })
    );
    runtime
        .execute_from_headers(
            &device_race_headers,
            Command::RevokeTrustedDevice(RevokeTrustedDevice {
                now: at(361),
                subject_id: id("device-race-subject"),
                device_credential_id: device_race_state
                    .trusted_device_credential_id
                    .clone()
                    .expect("device-race device id"),
                reason: RevocationReason::RemoteRevocation,
            }),
        )
        .await
        .expect("commit trusted-device revocation racing stale device rotation");
    let device_rotation_error =
        commit_planned_work_in_current_transaction_expect_precondition_error(
            &mut stale_device_rotation_tx,
            &store,
            &stale_device_rotation_plan,
        )
        .await;
    assert_precondition_failed(
        &device_rotation_error,
        "trusted device does not belong to subject",
    );
    stale_device_rotation_tx
        .rollback()
        .await
        .expect("roll back failed stale device-rotation transaction");
    assert_eq!(
        fetch_trusted_device_revoked_at(
            pool,
            store_config,
            &device_race_state
                .trusted_device_credential_id
                .clone()
                .expect("device-race device id"),
        )
        .await,
        Some(361)
    );
    assert_eq!(
        fetch_trusted_device_current_secret_version(
            pool,
            store_config,
            &device_race_state
                .trusted_device_credential_id
                .clone()
                .expect("device-race device id"),
        )
        .await,
        1,
        "failed stale device rotation must not advance the credential version"
    );
    assert_eq!(
        count_trusted_device_secret_macs_for_device(
            pool,
            store_config,
            &device_race_state
                .trusted_device_credential_id
                .clone()
                .expect("device-race device id"),
        )
        .await,
        1,
        "failed stale device rotation must not insert a replacement trusted-device secret MAC"
    );
    assert_eq!(
        count_sessions_for_session(pool, store_config, &id("device-race-stale-revival-session"))
            .await,
        0,
        "failed stale device rotation must not create its replacement session"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_stale_active_proof_commits_when_database_is_available() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let store = postgres_runtime_test_store(store_config);

    let challenge_completion_race = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "challenge-completion-race",
        20,
        id("challenge-completion-race-subject"),
    )
    .await;
    let challenge_completion_headers =
        headers_from_cookie_pairs(&[challenge_completion_race.challenge_cookie_pair.as_str()]);
    let mut stale_challenge_completion_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale challenge-completion transaction");
    let stale_challenge_completion_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_challenge_completion_tx,
        &store,
        &challenge_completion_headers,
        complete_out_of_band_challenge_command(
            &challenge_completion_race,
            at(40),
            id("challenge-completion-race-subject"),
        ),
    )
    .await;
    assert!(matches!(
        stale_challenge_completion_plan.planned.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(41),
                subject_id: id("challenge-completion-race-subject"),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("commit subject revocation racing challenge completion");
    let challenge_completion_error =
        commit_planned_work_in_current_transaction_expect_precondition_error(
            &mut stale_challenge_completion_tx,
            &store,
            &stale_challenge_completion_plan,
        )
        .await;
    assert_precondition_failed(
        &challenge_completion_error,
        "subject auth state invalidates target",
    );
    stale_challenge_completion_tx
        .rollback()
        .await
        .expect("roll back failed stale challenge-completion transaction");
    assert_eq!(
        count_satisfied_proofs_for_attempt(
            pool,
            store_config,
            &challenge_completion_race.attempt_id
        )
        .await,
        0,
        "failed stale challenge completion must not record a proof"
    );
    assert_eq!(
        count_open_challenges_for_challenge(
            pool,
            store_config,
            &challenge_completion_race.challenge_id
        )
        .await,
        1,
        "failed stale challenge completion must not close the challenge"
    );

    let resend_race_subject: SubjectId = id("resend-race-subject");
    let resend_race_session = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "resend-race-bootstrap",
        60,
        resend_race_subject.clone(),
        false,
    )
    .await;
    let resend_race = start_current_session_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "resend-race",
        90,
        resend_race_subject.clone(),
        resend_race_session.session_cookie_pair.as_str(),
    )
    .await;
    let mut stale_resend_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale resend transaction");
    let stale_resend_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_resend_tx,
        &store,
        &HeaderMap::new(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(110),
            attempt_id: resend_race.attempt_id.clone(),
            challenge_id: resend_race.challenge_id.clone(),
            idempotency_key: "resend-race-mail-idempotency-key-2".to_owned(),
            method_commit_work: Vec::new(),
        }),
    )
    .await;
    assert_eq!(
        stale_resend_plan.planned.outcome(),
        &Outcome::OutOfBandChallengeResent {
            attempt_id: resend_race.attempt_id.clone(),
            challenge_id: resend_race.challenge_id.clone(),
            resend_count: 1,
            expires_at: at(140),
        }
    );
    runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(111),
                subject_id: resend_race_subject,
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("commit subject revocation racing challenge resend");
    let resend_error = commit_planned_work_in_current_transaction_expect_precondition_error(
        &mut stale_resend_tx,
        &store,
        &stale_resend_plan,
    )
    .await;
    assert_precondition_failed(&resend_error, "subject auth state invalidates target");
    stale_resend_tx
        .rollback()
        .await
        .expect("roll back failed stale resend transaction");
    assert_eq!(
        fetch_out_of_band_challenge_resend_count(pool, store_config, &resend_race.challenge_id)
            .await,
        0,
        "failed stale resend must not advance resend count"
    );
    assert_eq!(
        count_challenge_delivery_keys(pool, store_config, &resend_race.challenge_id).await,
        1,
        "failed stale resend must not record a new delivery key"
    );

    let full_auth_race = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "full-auth-race",
        100,
        id("full-auth-race-subject"),
    )
    .await;
    complete_out_of_band_challenge_response_through_runtime(runtime, &full_auth_race, at(120))
        .await;
    let mut stale_full_auth_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale full-authentication transaction");
    let stale_full_auth_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_full_auth_tx,
        &store,
        &HeaderMap::new(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(125),
            attempt_id: full_auth_race.attempt_id.clone(),
            fresh_session_id: id("full-auth-race-session"),
            trust_device: None,
        }),
    )
    .await;
    assert_eq!(
        stale_full_auth_plan.planned.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: id("full-auth-race-subject"),
            session_id: id("full-auth-race-session"),
            source: AuthenticationSource::FullAuthentication,
            step_up_is_fresh: true,
        })
    );
    runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(126),
                subject_id: id("full-auth-race-subject"),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("commit subject revocation racing full authentication");
    let full_auth_error = commit_planned_work_in_current_transaction_expect_precondition_error(
        &mut stale_full_auth_tx,
        &store,
        &stale_full_auth_plan,
    )
    .await;
    assert_precondition_failed(&full_auth_error, "subject auth state invalidates target");
    stale_full_auth_tx
        .rollback()
        .await
        .expect("roll back failed stale full-authentication transaction");
    assert_eq!(
        count_sessions_for_session(pool, store_config, &id("full-auth-race-session")).await,
        0,
        "failed stale full authentication must not create a session"
    );
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &id("full-auth-race-session"))
            .await,
        0,
        "failed stale full authentication must not insert a session secret MAC"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &full_auth_race.attempt_id)
            .await,
        1,
        "failed stale full authentication must not delete the attempt"
    );

    let replay_race = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "replay-race",
        140,
        id("replay-race-subject"),
    )
    .await;
    let replay_headers = headers_from_cookie_pairs(&[replay_race.challenge_cookie_pair.as_str()]);
    let mut stale_replay_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale replay transaction");
    let stale_replay_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_replay_tx,
        &store,
        &replay_headers,
        complete_out_of_band_challenge_command(&replay_race, at(160), id("replay-race-subject")),
    )
    .await;
    assert!(matches!(
        stale_replay_plan.planned.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    complete_out_of_band_challenge_response_through_runtime(runtime, &replay_race, at(161)).await;
    let replay_error = commit_planned_work_in_current_transaction_expect_precondition_error(
        &mut stale_replay_tx,
        &store,
        &stale_replay_plan,
    )
    .await;
    assert_precondition_failed(&replay_error, "active proof challenge is no longer open");
    stale_replay_tx
        .rollback()
        .await
        .expect("roll back failed stale replay transaction");
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &replay_race.attempt_id).await,
        1,
        "stale replay must not duplicate the satisfied proof"
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &replay_race.challenge_id).await,
        0,
        "successful first completion must be the only challenge closure"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_commits_core_durable_effects_atomically_when_database_is_available() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;

    let challenge = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "durable-effect",
        20,
        id("durable-effect-subject"),
    )
    .await;
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        1
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(
            pool,
            store_config,
            &challenge.challenge_id
        )
        .await,
        1
    );

    let resent = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]),
            ResendOutOfBandChallengeRequest {
                now: at(40),
                idempotency_key: "durable-effect-mail-idempotency-key-2".to_owned(),
            },
        )
        .await
        .expect("resend challenge through Postgres runtime");
    assert!(matches!(
        resent.outcome(),
        Outcome::OutOfBandChallengeResent { .. }
    ));
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        2
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(
            pool,
            store_config,
            &challenge.challenge_id
        )
        .await,
        2
    );

    complete_out_of_band_challenge_response_through_runtime(runtime, &challenge, at(50)).await;
    let continuation_headers =
        headers_from_cookie_pairs(&[challenge.continuation_cookie_pair.as_str()]);
    let full_authentication = runtime
        .execute_full_authentication_completion_from_headers(
            &continuation_headers,
            CompleteFullAuthenticationInput {
                now: at(55),
                trust_device: Some(TrustDeviceAfterFullAuthenticationInput {
                    display_label: Some("durable effect browser".to_owned()),
                }),
            },
        )
        .await
        .expect("complete full authentication through Postgres runtime");
    assert!(matches!(
        full_authentication.outcome(),
        Outcome::Authenticated(_)
    ));
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        3
    );
    assert_eq!(
        count_security_notification_effects_for_subject(
            pool,
            store_config,
            &id("durable-effect-subject")
        )
        .await,
        1
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_method_facades_until_registry_is_configured_when_database_is_available()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let registry_runtime = &harness.runtime;
    let no_registry_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    let no_registry_runtime = super::super::postgres_runtime::PostgresAuthWebRuntime::new(
        AuthWebRuntime::new(config(), auth_web_transport()),
        pool.clone(),
        no_registry_store,
        Arc::new(hashcash_verifier_for_test()),
    );
    let runtime = &no_registry_runtime;
    let empty_headers = HeaderMap::new();
    let session_state_for_registry_errors = complete_full_authentication_through_runtime(
        registry_runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "method-registry-errors-bootstrap",
        10,
        id("method-registry-errors-subject"),
        false,
    )
    .await;
    let durable_effect_count_after_bootstrap =
        count_core_durable_effect_commands(pool, store_config).await;

    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        session_state_for_registry_errors
            .session_cookie_pair
            .as_str(),
        at(60),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);
    let issue_error = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &continuation_headers,
            IssueOutOfBandChallengeInput {
                now: at(70),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("method-issue:email-hash:window"),
                recipient_handle: "method-issue-opaque-email-handle".to_owned(),
                idempotency_key: "method-issue-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect_err("registered method must be required on challenge issue");
    assert_method_registry_not_configured(&issue_error);
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        durable_effect_count_after_bootstrap
    );

    let fused_issue_error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(40),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("method-fused-issue:email-hash:window"),
                recipient_handle: "method-fused-issue-opaque-email-handle".to_owned(),
                idempotency_key: "method-fused-issue-mail-idempotency-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(40)),
        )
        .await
        .expect_err("fused unbound start and issue must roll back when method registry is missing");
    assert_method_registry_not_configured(&fused_issue_error);
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 1);
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );

    harness.database_operation_observer.clear();
    let missing_cookie_resend_error = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &empty_headers,
            ResendOutOfBandChallengeRequest {
                now: at(40),
                idempotency_key: "method-resend-missing-cookie-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect_err("challenge resend must require the encrypted challenge cookie");
    assert!(matches!(
        missing_cookie_resend_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::MissingActiveProofChallengeCookie
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing out-of-band resend challenge cookie must reject before any database operation",
    );

    harness.database_operation_observer.clear();
    let malformed_cookie_resend_error = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &headers_from_cookie_pairs(&[
                "__Host-__paranoid_auth_active_proof_challenge=not-a-valid-encrypted-cookie",
            ]),
            ResendOutOfBandChallengeRequest {
                now: at(40),
                idempotency_key: "method-resend-malformed-cookie-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect_err("malformed challenge cookie must fail during transport decode");
    assert!(matches!(
        malformed_cookie_resend_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Web(_)
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "malformed out-of-band resend challenge cookie must reject before any database operation",
    );

    let message_signature_challenge_cookie =
        ActiveProofChallengeCookieDraft::new_without_response_mac(
            ActiveProofChallengeCookieContext::new(
                id("wrong-family-resend-attempt"),
                id("wrong-family-resend-challenge"),
                ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
                at(30),
                at(70),
                ActiveProofChallengeFastFailNonce::from_bytes(
                    &[88_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
                )
                .expect("nonce"),
            )
            .expect("message-signature challenge-cookie context"),
        )
        .expect("message-signature challenge cookie");
    let message_signature_challenge_effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofChallengeCookie(
            message_signature_challenge_cookie,
        ),
    ]);
    let message_signature_challenge_headers = auth_web_transport()
        .render_set_cookie_headers(at(30), message_signature_challenge_effects)
        .expect("message-signature challenge set-cookie headers");
    let message_signature_challenge_cookie_pair = cookie_pair_from_set_cookie(
        &message_signature_challenge_headers,
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    harness.database_operation_observer.clear();
    let wrong_family_resend_error = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &headers_from_cookie_pairs(&[message_signature_challenge_cookie_pair]),
            ResendOutOfBandChallengeRequest {
                now: at(40),
                idempotency_key: "method-resend-wrong-family-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect_err("non-out-of-band challenge cookie must fail before resend state load");
    assert!(matches!(
        wrong_family_resend_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofChallengeCookieProofFamilyCannotUseResponseSecret {
                family: ProofFamily::MessageSignature
            }
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "non-out-of-band resend challenge cookie must reject before any database operation",
    );

    let resend = start_and_issue_out_of_band_challenge_through_runtime(
        registry_runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "method-resend",
        60,
        id("method-resend-subject"),
    )
    .await;
    let resend_error = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &headers_from_cookie_pairs(&[resend.challenge_cookie_pair.as_str()]),
            ResendOutOfBandChallengeRequest {
                now: at(80),
                idempotency_key: "method-resend-mail-idempotency-key-2".to_owned(),
            },
        )
        .await
        .expect_err("registered method must be required on challenge resend");
    assert_method_registry_not_configured(&resend_error);
    assert_eq!(
        fetch_out_of_band_challenge_resend_count(pool, store_config, &resend.challenge_id).await,
        0
    );
    assert_eq!(
        count_challenge_delivery_keys(pool, store_config, &resend.challenge_id).await,
        1
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(pool, store_config, &resend.challenge_id)
            .await,
        1
    );

    harness.database_operation_observer.clear();
    let expired_cookie_resend_error = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &headers_from_cookie_pairs(&[resend.challenge_cookie_pair.as_str()]),
            ResendOutOfBandChallengeRequest {
                now: at(111),
                idempotency_key: "method-resend-expired-cookie-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect_err("expired challenge cookie must fail before method dispatch");
    assert!(matches!(
        expired_cookie_resend_error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofChallengeCookieExpired
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "expired out-of-band resend challenge cookie must reject before any database operation",
    );
    assert_eq!(
        fetch_out_of_band_challenge_resend_count(pool, store_config, &resend.challenge_id).await,
        0
    );
    assert_eq!(
        count_challenge_delivery_keys(pool, store_config, &resend.challenge_id).await,
        1
    );

    let completion = start_and_issue_out_of_band_challenge_through_runtime(
        registry_runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "method-completion",
        100,
        id("method-completion-subject"),
    )
    .await;
    let completion_headers =
        headers_from_cookie_pairs(&[completion.challenge_cookie_pair.as_str()]);
    let completion_error = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &completion_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(120),
                secret_response: ActiveProofChallengeResponseSecret::try_from(
                    completion.response_secret.expose_secret(),
                )
                .expect("challenge response secret"),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("registered method must be required on challenge completion");
    assert_method_registry_not_configured(&completion_error);
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &completion.attempt_id).await,
        0
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &completion.challenge_id).await,
        1
    );

    let known_subject_started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        session_state_for_registry_errors
            .session_cookie_pair
            .as_str(),
        at(130),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let known_subject_attempt_id = known_subject_started.attempt_id.clone();
    let known_subject_continuation_cookie_pair = known_subject_started.continuation_cookie_pair;
    let known_subject_headers =
        headers_from_cookie_pairs(&[known_subject_continuation_cookie_pair.as_str()]);
    let known_subject_method =
        ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp").expect("TOTP method");
    let known_subject_secret_response =
        known_subject_test_method_response_payload(&id("method-known-subject"));
    let known_subject_weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_known_subject_completion(
            &known_subject_headers,
            &known_subject_method,
            &known_subject_secret_response,
            at(140),
        );
    let known_subject_error = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &known_subject_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(140),
                method: known_subject_method,
                secret_response: known_subject_secret_response,
                weak_proof_gate_response: Some(known_subject_weak_proof_gate_response),
            },
        )
        .await
        .expect_err("registered method must be required on known-subject completion");
    assert_method_registry_not_configured(&known_subject_error);
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &known_subject_attempt_id,).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_commits_method_work_atomically_with_core_work_when_database_is_available()
{
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_method_plugin(Some(
        TestMethodCommitFailureMode::None,
    ))
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness.method_plugin.as_ref().expect("test method plugin");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &HeaderMap::new(),
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("method-atomic-success:email-hash:window"),
                recipient_handle: "method-atomic-success-recipient".to_owned(),
                idempotency_key: "method-atomic-success-mail-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue challenge with method registry");
    let success_challenge_id = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued { challenge_id, .. } => challenge_id.clone(),
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &success_challenge_id).await,
        1
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(pool, store_config, &success_challenge_id)
            .await,
        1
    );
    assert_eq!(method_plugin.count_state_rows(pool).await, 1);
    assert_eq!(method_plugin.count_durable_effect_rows(pool).await, 1);

    let precondition_error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &HeaderMap::new(),
            StartAndIssueOutOfBandChallengeInput {
                now: at(40),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key(
                    "method-atomic-precondition-failure:email-hash:window",
                ),
                recipient_handle: "method-atomic-precondition-failure-recipient".to_owned(),
                idempotency_key: "method-atomic-precondition-failure-mail-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(40)),
        )
        .await
        .expect_err("method precondition failure must abort the whole commit");
    assert_method_commit_work_failed(
        &precondition_error,
        super::super::postgres_store::PostgresAuthMethodCommitStage::EnforcePrecondition,
        "otp_state_absent",
    );
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        1
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        1
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 1);
    assert_eq!(method_plugin.count_state_rows(pool).await, 1);
    assert_eq!(method_plugin.count_durable_effect_rows(pool).await, 1);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rolls_back_core_work_when_method_mutation_fails_when_database_is_available()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_method_plugin(Some(
        TestMethodCommitFailureMode::FailMutation,
    ))
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness.method_plugin.as_ref().expect("test method plugin");

    let error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &HeaderMap::new(),
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("method-mutation-failure:email-hash:window"),
                recipient_handle: "method-mutation-failure-recipient".to_owned(),
                idempotency_key: "method-mutation-failure-mail-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect_err("method mutation failure must abort the whole commit");
    assert_method_commit_work_failed(
        &error,
        super::super::postgres_store::PostgresAuthMethodCommitStage::ApplyMutation,
        "store_otp_state",
    );
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        0
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);
    assert_eq!(method_plugin.count_state_rows(pool).await, 0);
    assert_eq!(method_plugin.count_durable_effect_rows(pool).await, 0);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rolls_back_core_work_when_method_durable_effect_fails_when_database_is_available()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_method_plugin(Some(
        TestMethodCommitFailureMode::FailDurableEffectCommand,
    ))
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness.method_plugin.as_ref().expect("test method plugin");

    let error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &HeaderMap::new(),
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("method-effect-failure:email-hash:window"),
                recipient_handle: "method-effect-failure-recipient".to_owned(),
                idempotency_key: "method-effect-failure-mail-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect_err("method durable effect failure must abort the whole commit");
    assert_method_commit_work_failed(
        &error,
        super::super::postgres_store::PostgresAuthMethodCommitStage::AppendDurableEffectCommand,
        "queue_email_body",
    );
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &id("method-effect-failure-challenge"))
            .await,
        0
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        0
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);
    assert_eq!(method_plugin.count_state_rows(pool).await, 0);
    assert_eq!(method_plugin.count_durable_effect_rows(pool).await, 0);

    harness.drop_schema().await;
}

fn auth_web_transport() -> AuthWebTransport {
    let cookie_manager =
        crate::web::CookieManager::from_keyset(test_keyset("tests.auth.postgres-runtime.web.v1"));
    let csrf_protector = crate::web::CsrfProtector::new(crate::web::CsrfProtectorConfig::new(
        cookie_manager.clone(),
    ))
    .expect("csrf protector");
    AuthWebTransport::new(AuthWebTransportConfig::new(
        cookie_manager,
        csrf_protector,
        test_keyset("tests.auth.postgres-runtime.fast-fail.v1"),
    ))
}

fn postgres_runtime_test_store(
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> super::super::postgres_store::PostgresAuthStore {
    super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    )
}

fn first_party_postgres_auth_bootstrap_for_test(
    db_bootstrap_config: BootstrapConfig,
) -> super::super::postgres_bootstrap::PostgresAuthBootstrap {
    super::super::postgres_bootstrap::PostgresAuthBootstrap::new(
        db_bootstrap_config,
        test_keyset("tests.auth.postgres-bootstrap.credentials.v1"),
    )
    .with_email_otp_method(
        test_keyset("tests.auth.postgres-bootstrap.email-otp.v1"),
        Arc::new(EmbeddedSubjectEmailOtpResolver),
    )
    .expect("add email otp method")
    .with_totp_method(
        test_keyset("tests.auth.postgres-bootstrap.totp.v1"),
        TestTotpCodeVerifier,
    )
    .expect("add totp method")
    .with_recovery_code_method(test_keyset(
        "tests.auth.postgres-bootstrap.recovery-code.v1",
    ))
    .expect("add recovery code method")
    .with_password_derived_signature_method()
    .expect("add password-derived signature method")
}

fn required_auth_postgres_runtime_test_database_url() -> String {
    std::env::var("PARANOID_TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DSN")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .expect("required auth Postgres runtime test database URL missing; run through the isolated DB harness so TEST_DSN or PARANOID_TEST_DATABASE_URL is set")
}

async fn auth_runtime_test_table_exists(
    pool: &Pool,
    schema: &PgSchemaName,
    table_name: &str,
) -> bool {
    let statement = r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = $1 AND table_name = $2
        )
    "#;
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<bool>(sqlx::AssertSqlSafe(statement))
            .bind(schema.as_str())
            .bind(table_name),
        "check auth runtime test table exists"
    )
}

async fn count_auth_schema_ledger_rows(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let schema_ledger_table = store_config
        .schema_ledger_table_name()
        .expect("auth schema ledger table name");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE component = $1 AND instance_key = $2",
        schema_ledger_table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind("auth_core")
            .bind(super::super::postgres_store::schema_instance_key(
                store_config,
            )),
        "count auth schema ledger rows"
    )
}

async fn drop_auth_runtime_test_schema(pool: &Pool, schema: &PgSchemaName) {
    let drop_schema = format!("DROP SCHEMA {} CASCADE", schema.identifier().quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop auth runtime test schema");
}

fn cookie_pair_from_set_cookie<'a>(
    headers: &'a AuthSetCookieHeaders,
    cookie_prefix: &str,
) -> &'a str {
    headers
        .as_slice()
        .iter()
        .find_map(|header| {
            header
                .as_str()
                .split(';')
                .next()
                .filter(|pair| pair.starts_with(cookie_prefix))
        })
        .expect("set-cookie pair")
}

fn active_proof_continuation_cookie_pair_from_set_cookie(headers: &AuthSetCookieHeaders) -> &str {
    cookie_pair_from_set_cookie(headers, "__Host-__paranoid_auth_active_proof_continuation=")
}

fn headers_from_cookie_pairs(cookie_pairs: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&cookie_pairs.join("; ")).expect("cookie header"),
    );
    headers
}

fn bound_proof_of_work_gate_response_for_active_method_completion(
    headers: &HeaderMap,
    response_payload: &ActiveProofMethodResponsePayload,
    now: UnixSeconds,
) -> WeakProofGateResponse {
    let decoded = auth_web_transport()
        .decode_presented_cookies_from_headers(headers)
        .expect("decode active-method challenge cookie for weak-gate binding");
    let challenge_cookie = decoded
        .presented_cookies()
        .active_proof_challenge_cookie
        .as_ref()
        .expect("active-method challenge cookie for weak-gate binding");
    let challenge_material = ActiveProofMethodChallengeMaterial::from_cookie(challenge_cookie)
        .expect("active-method challenge material for weak-gate binding");
    let binding =
        WeakProofGateBinding::for_active_method_response(&challenge_material, response_payload)
            .expect("active-method weak-gate binding");
    proof_of_work_gate_response_for_test(now, &challenge_material.proof, &binding)
}

fn bound_proof_of_work_gate_response_for_challenge_bound_totp_completion(
    headers: &HeaderMap,
    secret_response: &KnownSubjectActiveProofSecretResponse,
    now: UnixSeconds,
) -> WeakProofGateResponse {
    let decoded = auth_web_transport()
        .decode_presented_cookies_from_headers(headers)
        .expect("decode challenge-bound TOTP cookie for weak-gate binding");
    let challenge_cookie = decoded
        .presented_cookies()
        .active_proof_challenge_cookie
        .as_ref()
        .expect("challenge-bound TOTP cookie for weak-gate binding");
    let challenge_material = ActiveProofMethodChallengeMaterial::from_cookie(challenge_cookie)
        .expect("challenge-bound TOTP material for weak-gate binding");
    let binding = WeakProofGateBinding::for_challenge_bound_known_subject_secret_response(
        &challenge_material,
        secret_response,
    )
    .expect("challenge-bound TOTP weak-gate binding");
    proof_of_work_gate_response_for_test(now, &challenge_material.proof, &binding)
}

fn bound_proof_of_work_gate_response_for_known_subject_completion(
    headers: &HeaderMap,
    method: &ProofMethodDeclaration,
    secret_response: &KnownSubjectActiveProofSecretResponse,
    now: UnixSeconds,
) -> WeakProofGateResponse {
    let decoded = auth_web_transport()
        .decode_presented_cookies_from_headers(headers)
        .expect("decode continuation cookie for known-subject weak-gate binding");
    let continuation_cookie = decoded
        .presented_cookies()
        .active_proof_continuation_cookie
        .as_ref()
        .expect("continuation cookie for known-subject weak-gate binding");
    let proof = method.verified_proof_summary();
    let binding = WeakProofGateBinding::for_known_subject_secret_response(
        continuation_cookie,
        &proof,
        secret_response,
    )
    .expect("known-subject weak-gate binding");
    proof_of_work_gate_response_for_test(now, &proof, &binding)
}

fn set_cookie_headers_contain_deletion(
    headers: &AuthSetCookieHeaders,
    cookie_prefix: &str,
) -> bool {
    headers.as_slice().iter().any(|header| {
        header.as_str().starts_with(cookie_prefix) && header.as_str().contains("Max-Age=0")
    })
}

struct PlannedLoadedStateRuntimeCommand {
    planned: PlannedCommandExecution,
    planned_storage_boundary_contract: PlannedStorageBoundaryContract,
}

async fn plan_loaded_state_command_in_current_transaction(
    tx: &mut Tx<'_>,
    store: &super::super::postgres_store::PostgresAuthStore,
    headers: &HeaderMap,
    command: Command,
) -> PlannedLoadedStateRuntimeCommand {
    let now = command.now();
    let decoded = auth_web_transport()
        .decode_presented_cookies_from_headers(headers)
        .expect("decode presented cookies for stale runtime command");
    let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
    let prepared = PreparedCommandExecution::prepare(&config(), command, presented_cookies)
        .expect("prepare stale runtime command");
    let prepared_storage_boundary_contract =
        PreparedStorageBoundaryContract::for_prepared_command(&prepared);
    assert_eq!(
        prepared_storage_boundary_contract.boundary_before_reduce(),
        StorageBoundaryBeforeReduce::OpenBeforeStateLoad,
        "stale race test must keep the loaded-state transaction open through commit"
    );
    let loaded = store
        .load_state_in_current_transaction(
            tx,
            AuthLoadStateRequest::new(
                now,
                prepared.presented_cookies(),
                &presented_cookie_secrets,
                prepared.loaded_state_contract(),
                &prepared_storage_boundary_contract,
            ),
        )
        .await
        .expect("load stale runtime command state");
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("reduce stale runtime command");
    let planned_storage_boundary_contract = PlannedStorageBoundaryContract::for_planned_execution(
        &prepared_storage_boundary_contract,
        &planned,
    )
    .expect("build stale runtime command storage boundary");
    assert_eq!(
        planned_storage_boundary_contract.atomic_commit_boundary(),
        AtomicCommitBoundary::LoadedStateBoundary,
        "stale race test must commit through the loaded-state boundary"
    );
    PlannedLoadedStateRuntimeCommand {
        planned,
        planned_storage_boundary_contract,
    }
}

async fn commit_planned_work_in_current_transaction_expect_precondition_error(
    tx: &mut Tx<'_>,
    store: &super::super::postgres_store::PostgresAuthStore,
    planned: &PlannedLoadedStateRuntimeCommand,
) -> super::super::postgres_store::PostgresAuthStoreError {
    let request = AtomicCommitRequest::for_atomic_work_with_storage_boundary(
        planned.planned.atomic_commit_work(),
        planned.planned_storage_boundary_contract.clone(),
    )
    .expect("build stale runtime command commit request");
    store
        .commit_atomic_work_in_current_transaction(tx, request)
        .await
        .expect_err("stale runtime command commit must fail")
}

async fn seed_pending_credential_reset_for_runtime_test(
    pool: &Pool,
    store: &super::super::postgres_store::PostgresAuthStore,
    target_credential_id: VerifiedProofSourceId,
    email_authority: RecoveryAuthorityId,
    pending_action_id: PendingCredentialLifecycleActionId,
) {
    let transition = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context: credential_lifecycle_context(
                CredentialInstanceMetadata::new(
                    target_credential_id.clone(),
                    id("pending-reset-subject"),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialLifecycleState::Active,
                )
                .expect("pending reset credential metadata"),
                [CredentialRecoveryAuthority::new(
                    target_credential_id,
                    CredentialLifecycleAction::Reset,
                    email_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [out_of_band_identifier_lifecycle_evidence(
                    "pending-reset-email-source",
                    [email_authority],
                )],
            ),
            active_proof_attempt_to_close: None,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id,
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
            immediate_subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
        }),
        &LoadedState::default(),
    )
    .expect("plan pending credential reset");
    let (atomic_work, response_effects) = transition
        .commit_plan
        .try_into_validated_atomic_work_and_response_effects()
        .expect("valid pending reset atomic work");
    assert!(
        response_effects.is_empty(),
        "pending reset seed should not emit response-local effects"
    );
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin pending reset seed tx");
    let request = AtomicCommitRequest::for_atomic_work(&atomic_work)
        .expect("pending reset seed commit request");
    let commit_result = store
        .commit_atomic_work_in_current_transaction(&mut tx, request)
        .await;
    match commit_result {
        Ok(_) => tx.commit().await.expect("commit pending reset seed"),
        Err(error) => {
            tx.rollback().await.expect("rollback pending reset seed");
            panic!("commit pending reset seed failed: {error:?}");
        }
    }
}

fn assert_precondition_failed(
    error: &super::super::postgres_store::PostgresAuthStoreError,
    expected_reason: &'static str,
) {
    assert!(
        matches!(
            error,
            super::super::postgres_store::PostgresAuthStoreError::PreconditionFailed(reason)
                if *reason == expected_reason
        ),
        "expected precondition failure {expected_reason:?}, got {error:?}"
    );
}

fn assert_method_registry_not_configured(
    error: &super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError,
) {
    assert!(
        matches!(
            error,
            super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
                super::super::postgres_store::PostgresAuthStoreError::MethodRegistryNotConfigured
            )
        ),
        "expected unconfigured method registry error, got {error:?}"
    );
}

fn assert_method_commit_work_failed(
    error: &super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError,
    expected_stage: super::super::postgres_store::PostgresAuthMethodCommitStage,
    expected_operation: &'static str,
) {
    assert!(
        matches!(
            error,
            super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
                super::super::postgres_store::PostgresAuthStoreError::MethodCommitWorkFailed {
                    stage,
                    operation,
                    ..
                }
            )
                if *stage == expected_stage && operation == expected_operation
        ),
        "expected method commit work failure during {expected_stage:?} for {expected_operation}, got {error:?}"
    );
}

struct IssuedRuntimeAuth {
    session_id: SessionId,
    session_cookie_pair: String,
    trusted_device_credential_id: Option<TrustedDeviceCredentialId>,
    trusted_device_cookie_pair: Option<String>,
}

struct IssuedRuntimeChallenge {
    attempt_id: ActiveProofAttemptId,
    challenge_id: ActiveProofChallengeId,
    response_secret: ActiveProofChallengeResponseSecret,
    continuation_cookie_pair: String,
    challenge_cookie_pair: String,
}

struct IssuedRuntimeChallengeBoundTotpChallenge {
    attempt_id: ActiveProofAttemptId,
    challenge_id: ActiveProofChallengeId,
    challenge_cookie_pair: String,
}

struct StartedRuntimeAttempt {
    attempt_id: ActiveProofAttemptId,
    continuation_cookie_pair: String,
}

fn recipient_handle_for_test_subject(flow_label: &str, subject_id: &SubjectId) -> String {
    let subject_label = std::str::from_utf8(subject_id.as_bytes())
        .expect("test subject ids embedded in recipient handles must be UTF-8 labels");
    format!("{flow_label}-opaque-email-handle:subject:{subject_label}")
}

async fn start_current_session_active_proof_attempt_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    session_cookie_pair: &str,
    now: UnixSeconds,
    proof_use: ProofUse,
) -> StartedRuntimeAttempt {
    let headers = headers_from_cookie_pairs(&[session_cookie_pair]);
    let started = runtime
        .execute_current_session_active_proof_attempt_start_from_headers(
            &headers,
            StartCurrentSessionActiveProofAttemptInput { now, proof_use },
        )
        .await
        .expect("start active proof attempt from current session through Postgres runtime");
    let attempt_id = match started.outcome() {
        Outcome::ActiveProofAttemptStarted { attempt_id, .. } => attempt_id.clone(),
        outcome => panic!("expected active proof attempt start, got {outcome:?}"),
    };
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(started.set_cookie_headers())
            .to_owned();
    StartedRuntimeAttempt {
        attempt_id,
        continuation_cookie_pair,
    }
}

async fn start_and_issue_out_of_band_challenge_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    pool: &Pool,
    email_otp: &PostgresEmailOtpMethodPlugin,
    flow_label: &str,
    start_at: u64,
    subject_id: SubjectId,
) -> IssuedRuntimeChallenge {
    let empty_headers = HeaderMap::new();

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(start_at + 10),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key(&format!("{flow_label}:email-hash:window")),
                recipient_handle: recipient_handle_for_test_subject(flow_label, &subject_id),
                idempotency_key: format!("{flow_label}-mail-idempotency-key"),
            },
            email_otp_challenge_issue_preflight_response_at(at(start_at + 10)),
        )
        .await
        .expect("issue challenge through Postgres runtime");
    let (attempt_id, challenge_id) = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            ..
        } => (attempt_id.clone(), challenge_id.clone()),
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(issued.set_cookie_headers())
            .to_owned();
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();

    IssuedRuntimeChallenge {
        attempt_id,
        challenge_id,
        response_secret,
        continuation_cookie_pair,
        challenge_cookie_pair,
    }
}

async fn start_current_session_and_issue_out_of_band_challenge_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    pool: &Pool,
    email_otp: &PostgresEmailOtpMethodPlugin,
    flow_label: &str,
    start_at: u64,
    subject_id: SubjectId,
    session_cookie_pair: &str,
) -> IssuedRuntimeChallenge {
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        session_cookie_pair,
        at(start_at),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);

    let issued = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &continuation_headers,
            IssueOutOfBandChallengeInput {
                now: at(start_at + 10),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key(&format!("{flow_label}:email-hash:window")),
                recipient_handle: recipient_handle_for_test_subject(flow_label, &subject_id),
                idempotency_key: format!("{flow_label}-mail-idempotency-key"),
            },
        )
        .await
        .expect("issue subject-bound challenge through Postgres runtime");
    let challenge_id = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued { challenge_id, .. } => challenge_id.clone(),
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();

    IssuedRuntimeChallenge {
        attempt_id: started.attempt_id,
        challenge_id,
        response_secret,
        continuation_cookie_pair: started.continuation_cookie_pair,
        challenge_cookie_pair,
    }
}

async fn start_current_session_and_issue_challenge_bound_totp_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    session_cookie_pair: &str,
    attempt_start_at: UnixSeconds,
    challenge_issue_at: UnixSeconds,
) -> IssuedRuntimeChallengeBoundTotpChallenge {
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        session_cookie_pair,
        attempt_start_at,
        ProofUse::SatisfyStepUp,
    )
    .await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);
    let issued = runtime
        .execute_challenge_bound_known_subject_active_proof_method_challenge_issue_from_headers(
            &continuation_headers,
            IssueChallengeBoundKnownSubjectActiveProofMethodChallengeInput {
                now: challenge_issue_at,
                method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
                    .expect("TOTP method"),
                method_challenge_request_payload: None,
            },
        )
        .await
        .expect("issue challenge-bound TOTP challenge through Postgres runtime");
    let challenge_id = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            challenge_id,
            proof,
            ..
        } => {
            assert_eq!(attempt_id, &started.attempt_id);
            assert_eq!(
                proof,
                &ProofSummary::new(ProofFamily::SharedSecretOtp, "totp").expect("proof"),
            );
            challenge_id.clone()
        }
        outcome => panic!("expected challenge-bound TOTP challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();

    IssuedRuntimeChallengeBoundTotpChallenge {
        attempt_id: started.attempt_id,
        challenge_id,
        challenge_cookie_pair,
    }
}

async fn complete_out_of_band_challenge_response_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    challenge: &IssuedRuntimeChallenge,
    now: UnixSeconds,
) -> AuthWebRuntimeExecution {
    let headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers,
            CompleteOutOfBandChallengeResponse {
                now,
                secret_response: ActiveProofChallengeResponseSecret::try_from(
                    challenge.response_secret.expose_secret(),
                )
                .expect("challenge response secret"),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete challenge through Postgres runtime");
    assert!(matches!(
        completed.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    completed
}

fn complete_out_of_band_challenge_command(
    challenge: &IssuedRuntimeChallenge,
    now: UnixSeconds,
    subject_id: SubjectId,
) -> Command {
    let proof = ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof");
    Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
        now,
        attempt_id: challenge.attempt_id.clone(),
        challenge_id: Some(challenge.challenge_id.clone()),
        verified_proof: VerifiedActiveProof::from_summary(proof, Some(subject_id))
            .expect("verified out-of-band proof"),
        stateless_fast_fail: verified_stateless_fast_fail(),
        weak_proof_gate: WeakProofGateStatus::NotRequired,
        method_commit_work: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn complete_full_authentication_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    email_otp: &PostgresEmailOtpMethodPlugin,
    flow_label: &str,
    start_at: u64,
    subject_id: SubjectId,
    trust_device: bool,
) -> IssuedRuntimeAuth {
    let empty_headers = HeaderMap::new();

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(start_at),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key(&format!("{flow_label}:email-hash:window")),
                recipient_handle: recipient_handle_for_test_subject(flow_label, &subject_id),
                idempotency_key: format!("{flow_label}-mail-idempotency-key"),
            },
            email_otp_challenge_issue_preflight_response_at(at(start_at)),
        )
        .await
        .expect("issue challenge through Postgres runtime");
    let challenge_id = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued { challenge_id, .. } => challenge_id.clone(),
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(issued.set_cookie_headers())
            .to_owned();
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let challenge_headers = headers_from_cookie_pairs(&[challenge_cookie_pair]);

    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &challenge_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(start_at + 20),
                secret_response: response_secret,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete challenge through Postgres runtime");
    assert!(matches!(
        completed.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));

    let full_authentication = runtime
        .execute_full_authentication_completion_from_headers(
            &continuation_headers,
            CompleteFullAuthenticationInput {
                now: at(start_at + 25),
                trust_device: trust_device.then(|| TrustDeviceAfterFullAuthenticationInput {
                    display_label: Some(format!("{flow_label} test browser")),
                }),
            },
        )
        .await
        .expect("complete full authentication through Postgres runtime");
    let session_id = match full_authentication.outcome() {
        Outcome::Authenticated(authenticated) => authenticated.session_id.clone(),
        outcome => panic!("expected full authentication, got {outcome:?}"),
    };
    let session_cookie_pair = cookie_pair_from_set_cookie(
        full_authentication.set_cookie_headers(),
        "__Host-__paranoid_auth_session=",
    )
    .to_owned();
    let trusted_device_cookie_pair = full_authentication
        .set_cookie_headers()
        .as_slice()
        .iter()
        .find_map(|header| {
            header
                .as_str()
                .split(';')
                .next()
                .filter(|pair| pair.starts_with("__Host-__paranoid_auth_trusted_device="))
                .map(str::to_owned)
        });
    let trusted_device_credential_id = if trust_device {
        Some(
            fetch_trusted_device_id_by_display_label(
                pool,
                store_config,
                &format!("{flow_label} test browser"),
            )
            .await
            .expect("trusted device id by display label"),
        )
    } else {
        None
    };

    IssuedRuntimeAuth {
        session_id,
        session_cookie_pair,
        trusted_device_credential_id,
        trusted_device_cookie_pair,
    }
}

async fn count_satisfied_proofs_for_attempt(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    attempt_id: &ActiveProofAttemptId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofSatisfiedProof)
        .expect("satisfied proof table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE attempt_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(attempt_id.as_bytes()),
        "count satisfied proofs"
    )
}

async fn fetch_satisfied_proof_source_for_attempt(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    attempt_id: &ActiveProofAttemptId,
) -> Option<VerifiedProofSource> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofSatisfiedProof)
        .expect("satisfied proof table");
    let statement = format!(
        "SELECT proof_source_kind, proof_source_id FROM {} WHERE attempt_id = $1",
        table.quoted()
    );
    let row = auth_runtime_test_fetch_optional_in_transaction!(
        pool,
        pooler_safe_query_as::<(Option<i32>, Option<Vec<u8>>)>(sqlx::AssertSqlSafe(
            statement.as_str(),
        ))
        .bind(attempt_id.as_bytes()),
        "fetch satisfied proof source"
    )?;
    match row {
        (None, None) => None,
        (Some(kind), Some(source_id)) => Some(VerifiedProofSource::new(
            super::super::postgres_store::verified_proof_source_kind_from_i32(kind)
                .expect("parse proof source kind"),
            VerifiedProofSourceId::from_bytes(source_id).expect("parse proof source id"),
        )),
        _ => panic!("satisfied proof source kind/id must both be present or both absent"),
    }
}

async fn fetch_active_proof_attempt_subject_id(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    attempt_id: &ActiveProofAttemptId,
) -> Option<SubjectId> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofAttempt)
        .expect("active proof attempt table");
    let statement = format!(
        "SELECT subject_id FROM {} WHERE attempt_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_optional_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<Vec<u8>>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(attempt_id.as_bytes()),
        "fetch active proof attempt subject"
    )
    .flatten()
    .map(SubjectId::from_bytes)
    .transpose()
    .expect("parse subject id")
}

async fn count_open_pending_credential_reset_actions_for_target(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    target_credential_instance_id: &VerifiedProofSourceId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
        .expect("pending credential lifecycle action table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE target_credential_instance_id = $1 AND lifecycle_action = $2 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(target_credential_instance_id.as_bytes())
            .bind(
                super::super::postgres_store::i32_from_credential_lifecycle_action(
                    CredentialLifecycleAction::Reset,
                ),
            ),
        "count open pending credential reset actions for target"
    )
}

async fn count_open_pending_credential_reset_actions_for_pending_action(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    pending_action_id: &PendingCredentialLifecycleActionId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
        .expect("pending credential lifecycle action table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE pending_action_id = $1 AND lifecycle_action = $2 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(pending_action_id.as_bytes())
            .bind(
                super::super::postgres_store::i32_from_credential_lifecycle_action(
                    CredentialLifecycleAction::Reset,
                ),
            ),
        "count open pending credential reset actions for pending action"
    )
}

async fn pending_credential_reset_closed_at_for_pending_action(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    pending_action_id: &PendingCredentialLifecycleActionId,
) -> Option<i64> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
        .expect("pending credential lifecycle action table");
    let statement = format!(
        "SELECT closed_at FROM {} WHERE pending_action_id = $1 AND lifecycle_action = $2",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<i64>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(pending_action_id.as_bytes())
            .bind(
                super::super::postgres_store::i32_from_credential_lifecycle_action(
                    CredentialLifecycleAction::Reset,
                ),
            ),
        "read pending credential reset closed_at"
    )
}

async fn count_open_pending_credential_lifecycle_actions_for_pending_action(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    pending_action_id: &PendingCredentialLifecycleActionId,
    action: CredentialLifecycleAction,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
        .expect("pending credential lifecycle action table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE pending_action_id = $1 AND lifecycle_action = $2 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(pending_action_id.as_bytes())
            .bind(super::super::postgres_store::i32_from_credential_lifecycle_action(action),),
        "count open pending credential lifecycle actions for pending action"
    )
}

async fn count_open_pending_subject_lifecycle_actions_for_pending_action(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    pending_action_id: &PendingSubjectLifecycleActionId,
    action: SubjectLifecycleAction,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingSubjectLifecycleAction)
        .expect("pending subject lifecycle action table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE pending_action_id = $1 AND subject_lifecycle_action = $2 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(pending_action_id.as_bytes())
            .bind(super::super::postgres_store::i32_from_subject_lifecycle_action(action),),
        "count open pending subject lifecycle actions for pending action"
    )
}

async fn credential_lifecycle_state_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    credential_instance_id: &VerifiedProofSourceId,
) -> CredentialLifecycleState {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CredentialInstance)
        .expect("credential instance table");
    let statement = format!(
        "SELECT lifecycle_state FROM {} WHERE credential_instance_id = $1",
        table.quoted()
    );
    let raw_state = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(credential_instance_id.as_bytes()),
        "read credential lifecycle state"
    );
    super::super::postgres_store::credential_lifecycle_state_from_i32(raw_state)
        .expect("stored credential lifecycle state")
}

async fn count_open_challenges(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    count_open_challenges_for_challenge(pool, store_config, &id("challenge")).await
}

async fn count_open_challenges_for_challenge(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    challenge_id: &ActiveProofChallengeId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("challenge table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE challenge_id = $1 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes()),
        "count open challenges"
    )
}

async fn count_challenges_for_challenge(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    challenge_id: &ActiveProofChallengeId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("challenge table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE challenge_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes()),
        "count challenges"
    )
}

async fn fetch_out_of_band_challenge_resend_count(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    challenge_id: &ActiveProofChallengeId,
) -> u32 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("challenge table");
    let statement = format!(
        "SELECT resend_count FROM {} WHERE challenge_id = $1",
        table.quoted()
    );
    let stored = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes()),
        "fetch challenge resend count"
    );
    u32::try_from(stored).expect("stored resend count must fit u32")
}

async fn count_challenge_delivery_keys(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    challenge_id: &ActiveProofChallengeId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey)
        .expect("challenge delivery key table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE challenge_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes()),
        "count challenge delivery keys"
    )
}

async fn count_core_durable_effect_commands(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)
        .expect("core durable effect command table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count core durable effect commands"
    )
}

async fn count_all_active_proof_attempts(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofAttempt)
        .expect("active proof attempt table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count active proof attempts"
    )
}

async fn count_all_active_proof_challenges(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("active proof challenge table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count active proof challenges"
    )
}

async fn count_out_of_band_durable_effects_for_challenge(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    challenge_id: &ActiveProofChallengeId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)
        .expect("core durable effect command table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE challenge_id = $1 AND delivery_idempotency_key IS NOT NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes()),
        "count out-of-band durable effects"
    )
}

async fn count_security_notification_effects_for_subject(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)
        .expect("core durable effect command table");
    let statement = format!(
        r#"
        SELECT count(*) FROM {}
        WHERE subject_id = $1
            AND challenge_id IS NULL
            AND delivery_idempotency_key IS NULL
        "#,
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes()),
        "count security notification effects"
    )
}

async fn count_all_sessions(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::Session)
        .expect("session table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count sessions"
    )
}

async fn count_sessions_for_session(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    session_id: &SessionId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::Session)
        .expect("session table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE session_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(session_id.as_bytes()),
        "count sessions for session"
    )
}

async fn count_session_secret_macs_for_session(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    session_id: &SessionId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::SessionCredentialSecretMac)
        .expect("session secret MAC table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE session_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(session_id.as_bytes()),
        "count session secret MACs"
    )
}

async fn count_all_trusted_devices(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredential)
        .expect("trusted device table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count trusted devices"
    )
}

async fn count_trusted_device_secret_macs_for_device(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    device_credential_id: &TrustedDeviceCredentialId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac)
        .expect("trusted device secret MAC table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE device_credential_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(device_credential_id.as_bytes()),
        "count trusted device secret MACs"
    )
}

async fn fetch_trusted_device_id_by_display_label(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    display_label: &str,
) -> Option<TrustedDeviceCredentialId> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredential)
        .expect("trusted device table");
    let statement = format!(
        "SELECT device_credential_id FROM {} WHERE display_label = $1",
        table.quoted()
    );
    let bytes = auth_runtime_test_fetch_optional_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Vec<u8>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(display_label),
        "fetch trusted device id by display label"
    )?;
    Some(TrustedDeviceCredentialId::from_bytes(bytes).expect("trusted device id bytes"))
}

async fn fetch_trusted_device_current_secret_version(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    device_credential_id: &TrustedDeviceCredentialId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredential)
        .expect("trusted device table");
    let statement = format!(
        "SELECT current_secret_version FROM {} WHERE device_credential_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(device_credential_id.as_bytes()),
        "fetch trusted device current secret version"
    )
}

async fn fetch_session_revoked_at(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    session_id: &SessionId,
) -> Option<u64> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::Session)
        .expect("session table");
    let statement = format!(
        "SELECT revoked_at FROM {} WHERE session_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<i64>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(session_id.as_bytes()),
        "fetch session revoked_at"
    )
    .map(|value| u64::try_from(value).expect("stored revoked_at must fit u64"))
}

async fn fetch_trusted_device_revoked_at(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    device_credential_id: &TrustedDeviceCredentialId,
) -> Option<u64> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredential)
        .expect("trusted device table");
    let statement = format!(
        "SELECT revoked_at FROM {} WHERE device_credential_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<i64>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(device_credential_id.as_bytes()),
        "fetch trusted device revoked_at"
    )
    .map(|value| u64::try_from(value).expect("stored revoked_at must fit u64"))
}

async fn fetch_subject_revocation_cutoff(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
) -> Option<u64> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::SubjectAuthState)
        .expect("subject auth state table");
    let statement = format!(
        "SELECT revoke_records_created_at_or_before FROM {} WHERE subject_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<i64>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes()),
        "fetch subject revocation cutoff"
    )
    .map(|value| u64::try_from(value).expect("stored cutoff must fit u64"))
}

async fn count_active_proof_attempts_for_attempt(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    attempt_id: &ActiveProofAttemptId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofAttempt)
        .expect("active proof attempt table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE attempt_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(attempt_id.as_bytes()),
        "count active proof attempts"
    )
}

async fn fetch_active_proof_attempt_weak_failures(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    attempt_id: &ActiveProofAttemptId,
) -> Option<i32> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofAttempt)
        .expect("active proof attempt table");
    let statement = format!(
        "SELECT weak_proof_failures FROM {} WHERE attempt_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_optional_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(attempt_id.as_bytes()),
        "fetch active proof attempt weak failures"
    )
}

fn unique_runtime_test_schema_name() -> PgIdentifier {
    let counter = AUTH_POSTGRES_RUNTIME_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    PgIdentifier::new(format!(
        "__paranoid_auth_runtime_test_{}_{}",
        std::process::id(),
        counter
    ))
    .expect("test schema name")
}

fn test_keyset(purpose: &str) -> crate::crypto::Keyset {
    let key =
        crate::crypto::Key32::try_from([37_u8; crate::crypto::KEY32_SIZE].as_slice()).expect("key");
    crate::crypto::derive_keyset_from_latest_first_keys([key], purpose).expect("keyset")
}
