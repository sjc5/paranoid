use std::fmt;
use std::sync::Arc;

use crate::crypto::Keyset;
use crate::db::{BootstrapConfig, Pool, WritePool};

use super::email_otp_method::{
    PostgresEmailOtpMethodError, PostgresEmailOtpMethodPlugin, PostgresEmailOtpMethodPluginConfig,
    PostgresEmailOtpSubjectResolver,
};
use super::postgres_method_runtime::{
    PostgresAuthMethodPlugin, PostgresAuthMethodRegistry, PostgresAuthMethodRegistryError,
};
use super::postgres_password_derived_signature_method::{
    PostgresPasswordDerivedSignatureMethodError, PostgresPasswordDerivedSignatureMethodPlugin,
    PostgresPasswordDerivedSignatureMethodPluginConfig,
};
use super::postgres_recovery_code_method::{
    PostgresRecoveryCodeMethodError, PostgresRecoveryCodeMethodPlugin,
    PostgresRecoveryCodeMethodPluginConfig,
};
use super::postgres_runtime::PostgresAuthWebRuntime;
use super::postgres_store::{PostgresAuthStore, PostgresAuthStoreConfig, PostgresAuthStoreError};
use super::postgres_totp_method::{
    PostgresTotpCodeVerifier, PostgresTotpMethodError, PostgresTotpMethodPlugin,
    PostgresTotpMethodPluginConfig, StandardTotpCodeVerifier,
};
use super::{
    AuthSystemConfig, AuthWebRuntime, Error, PostgresAuthSystem, PostgresAuthSystemConfig,
    WeakProofGateVerifier,
};
use super::{
    MountedAuthPostgresMethodSetup, MountedAuthPostgresRuntime, MountedAuthPostgresSystem,
    MountedAuthRuntimeConfig, MountedAuthRuntimeError, MountedAuthSystemConfig,
};

pub(crate) struct PostgresAuthBootstrap {
    db_bootstrap_config: BootstrapConfig,
    credential_secret_keyset: Keyset,
    method_plugins: Vec<Arc<dyn PostgresAuthMethodPlugin>>,
}

impl PostgresAuthBootstrap {
    pub(crate) fn new(
        db_bootstrap_config: BootstrapConfig,
        credential_secret_keyset: Keyset,
    ) -> Self {
        Self {
            db_bootstrap_config,
            credential_secret_keyset,
            method_plugins: Vec::new(),
        }
    }

    pub(crate) fn with_email_otp_method(
        mut self,
        response_secret_keyset: Keyset,
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Result<Self, PostgresAuthBootstrapError> {
        let plugin = PostgresEmailOtpMethodPlugin::new(
            PostgresEmailOtpMethodPluginConfig::for_db_bootstrap_config(&self.db_bootstrap_config)?,
            response_secret_keyset,
        )?
        .with_subject_resolver(subject_resolver);
        self.method_plugins.push(Arc::new(plugin));
        Ok(self)
    }

    pub(crate) fn with_totp_method<V>(
        mut self,
        secret_keyset: Keyset,
        verifier: V,
    ) -> Result<Self, PostgresAuthBootstrapError>
    where
        V: PostgresTotpCodeVerifier + 'static,
    {
        let plugin = PostgresTotpMethodPlugin::new(
            PostgresTotpMethodPluginConfig::for_db_bootstrap_config(&self.db_bootstrap_config)?,
            secret_keyset,
            verifier,
        )?;
        self.method_plugins.push(Arc::new(plugin));
        Ok(self)
    }

    pub(crate) fn with_standard_totp_method(
        self,
        secret_keyset: Keyset,
    ) -> Result<Self, PostgresAuthBootstrapError> {
        self.with_totp_method(secret_keyset, StandardTotpCodeVerifier::default())
    }

    pub(crate) fn with_recovery_code_method(
        mut self,
        secret_keyset: Keyset,
    ) -> Result<Self, PostgresAuthBootstrapError> {
        let plugin = PostgresRecoveryCodeMethodPlugin::new(
            PostgresRecoveryCodeMethodPluginConfig::for_db_bootstrap_config(
                &self.db_bootstrap_config,
            )?,
            secret_keyset,
        )?;
        self.method_plugins.push(Arc::new(plugin));
        Ok(self)
    }

    pub(crate) fn with_password_derived_signature_method(
        mut self,
    ) -> Result<Self, PostgresAuthBootstrapError> {
        let plugin = PostgresPasswordDerivedSignatureMethodPlugin::new(
            PostgresPasswordDerivedSignatureMethodPluginConfig::for_db_bootstrap_config(
                &self.db_bootstrap_config,
            )?,
        )?;
        self.method_plugins.push(Arc::new(plugin));
        Ok(self)
    }

    pub(crate) fn auth_store_config(
        &self,
    ) -> Result<PostgresAuthStoreConfig, PostgresAuthBootstrapError> {
        Ok(PostgresAuthStoreConfig::for_db_bootstrap_config(
            &self.db_bootstrap_config,
        )?)
    }

    fn with_mounted_system_method_setup(
        self,
        method_setup: MountedAuthPostgresMethodSetup,
    ) -> Result<Self, PostgresAuthBootstrapError> {
        match method_setup {
            MountedAuthPostgresMethodSetup::EmailOtp {
                response_secret_keyset,
                subject_resolver,
            } => self.with_email_otp_method(response_secret_keyset, subject_resolver),
            MountedAuthPostgresMethodSetup::Totp {
                secret_keyset,
                verifier,
            } => self.with_totp_method(secret_keyset, verifier),
            MountedAuthPostgresMethodSetup::RecoveryCode { secret_keyset } => {
                self.with_recovery_code_method(secret_keyset)
            }
            MountedAuthPostgresMethodSetup::PasswordDerivedSignature => {
                self.with_password_derived_signature_method()
            }
        }
    }

    fn with_mounted_system_method_setups(
        mut self,
        method_setups: Vec<MountedAuthPostgresMethodSetup>,
    ) -> Result<Self, PostgresAuthBootstrapError> {
        for method_setup in method_setups {
            self = self.with_mounted_system_method_setup(method_setup)?;
        }
        Ok(self)
    }

    fn into_store_for_already_bootstrapped_db_foundation(
        self,
    ) -> Result<PostgresAuthStore, PostgresAuthBootstrapError> {
        let mut store = PostgresAuthStore::new(
            PostgresAuthStoreConfig::for_db_bootstrap_config(&self.db_bootstrap_config)?,
            self.credential_secret_keyset,
        );
        if !self.method_plugins.is_empty() {
            let registry = PostgresAuthMethodRegistry::new(self.method_plugins)?;
            store = store.with_method_registry(Arc::new(registry));
        }
        Ok(store)
    }

    pub(crate) async fn migrate_schema_after_db_bootstrap(
        self,
        pool: &WritePool,
    ) -> Result<PostgresAuthStore, PostgresAuthBootstrapError> {
        let store = self.into_store_for_already_bootstrapped_db_foundation()?;
        store.migrate_schema(pool).await?;
        Ok(store)
    }

    pub(crate) async fn validate_schema_after_db_bootstrap(
        self,
        pool: &Pool,
    ) -> Result<(), PostgresAuthBootstrapError> {
        self.into_store_for_already_bootstrapped_db_foundation()?
            .validate_schema(pool)
            .await?;
        Ok(())
    }

    async fn migrate_schema_and_build_web_runtime_after_db_bootstrap(
        self,
        write_pool: &WritePool,
        pool: Pool,
        runtime: AuthWebRuntime,
        weak_proof_gate_verifier: Arc<dyn WeakProofGateVerifier + Send + Sync>,
    ) -> Result<PostgresAuthWebRuntime, PostgresAuthBootstrapError> {
        let store = self.into_store_for_already_bootstrapped_db_foundation()?;
        store.migrate_schema(write_pool).await?;
        Ok(PostgresAuthWebRuntime::new(
            runtime,
            pool,
            store,
            weak_proof_gate_verifier,
        ))
    }

    async fn migrate_schema_and_build_mounted_runtime_after_db_bootstrap(
        self,
        write_pool: &WritePool,
        pool: Pool,
        runtime: AuthWebRuntime,
        weak_proof_gate_verifier: Arc<dyn WeakProofGateVerifier + Send + Sync>,
        mounted_config: MountedAuthRuntimeConfig,
    ) -> Result<MountedAuthPostgresRuntime, PostgresAuthBootstrapError> {
        let runtime = self
            .migrate_schema_and_build_web_runtime_after_db_bootstrap(
                write_pool,
                pool,
                runtime,
                weak_proof_gate_verifier,
            )
            .await?;
        Ok(MountedAuthPostgresRuntime::try_new(
            runtime,
            mounted_config,
        )?)
    }

    async fn migrate_schema_and_build_mounted_system_after_db_bootstrap(
        self,
        write_pool: &WritePool,
        pool: Pool,
        mounted_system_config: MountedAuthSystemConfig,
    ) -> Result<MountedAuthPostgresSystem, PostgresAuthBootstrapError> {
        let (runtime, weak_proof_gate_verifier, configured_system, method_setups) =
            mounted_system_config.into_runtime_and_configured_system();
        let bootstrap = self.with_mounted_system_method_setups(method_setups)?;
        let (mount_path, mounted_config) =
            configured_system.into_mount_path_and_runtime_config()?;
        let runtime = bootstrap
            .migrate_schema_and_build_mounted_runtime_after_db_bootstrap(
                write_pool,
                pool,
                runtime,
                weak_proof_gate_verifier,
                mounted_config,
            )
            .await?;
        Ok(MountedAuthPostgresSystem::new(runtime, mount_path))
    }

    pub(crate) async fn migrate_schema_and_build_auth_system_after_db_bootstrap(
        self,
        write_pool: &WritePool,
        pool: Pool,
        auth_system_config: AuthSystemConfig,
    ) -> Result<PostgresAuthSystem, PostgresAuthBootstrapError> {
        let mounted_system = self
            .migrate_schema_and_build_mounted_system_after_db_bootstrap(
                write_pool,
                pool,
                auth_system_config.into_mounted_config(),
            )
            .await?;
        Ok(PostgresAuthSystem::new(mounted_system))
    }
}

impl PostgresAuthSystemConfig {
    pub(crate) async fn migrate_schema_and_build_after_db_bootstrap(
        self,
        write_pool: &WritePool,
        pool: Pool,
    ) -> Result<PostgresAuthSystem, PostgresAuthBootstrapError> {
        let (db_bootstrap_config, credential_secret_keyset, auth_system_config) = self.into_parts();
        PostgresAuthBootstrap::new(db_bootstrap_config, credential_secret_keyset)
            .migrate_schema_and_build_auth_system_after_db_bootstrap(
                write_pool,
                pool,
                auth_system_config,
            )
            .await
    }
}

#[derive(Debug)]
pub(crate) enum PostgresAuthBootstrapError {
    Config(Error),
    EmailOtp(PostgresEmailOtpMethodError),
    MethodRegistry(PostgresAuthMethodRegistryError),
    PasswordDerivedSignature(PostgresPasswordDerivedSignatureMethodError),
    RecoveryCode(PostgresRecoveryCodeMethodError),
    Store(PostgresAuthStoreError),
    Totp(PostgresTotpMethodError),
    MountedRuntime(MountedAuthRuntimeError),
}

impl fmt::Display for PostgresAuthBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::EmailOtp(error) => write!(f, "{error}"),
            Self::MethodRegistry(error) => write!(f, "{error}"),
            Self::PasswordDerivedSignature(error) => write!(f, "{error}"),
            Self::RecoveryCode(error) => write!(f, "{error}"),
            Self::Store(error) => write!(f, "{error}"),
            Self::Totp(error) => write!(f, "{error}"),
            Self::MountedRuntime(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PostgresAuthBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::EmailOtp(error) => Some(error),
            Self::MethodRegistry(error) => Some(error),
            Self::PasswordDerivedSignature(error) => Some(error),
            Self::RecoveryCode(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Totp(error) => Some(error),
            Self::MountedRuntime(error) => Some(error),
        }
    }
}

impl From<Error> for PostgresAuthBootstrapError {
    fn from(error: Error) -> Self {
        Self::Config(error)
    }
}

impl From<PostgresEmailOtpMethodError> for PostgresAuthBootstrapError {
    fn from(error: PostgresEmailOtpMethodError) -> Self {
        Self::EmailOtp(error)
    }
}

impl From<PostgresAuthMethodRegistryError> for PostgresAuthBootstrapError {
    fn from(error: PostgresAuthMethodRegistryError) -> Self {
        Self::MethodRegistry(error)
    }
}

impl From<PostgresPasswordDerivedSignatureMethodError> for PostgresAuthBootstrapError {
    fn from(error: PostgresPasswordDerivedSignatureMethodError) -> Self {
        Self::PasswordDerivedSignature(error)
    }
}

impl From<PostgresRecoveryCodeMethodError> for PostgresAuthBootstrapError {
    fn from(error: PostgresRecoveryCodeMethodError) -> Self {
        Self::RecoveryCode(error)
    }
}

impl From<PostgresAuthStoreError> for PostgresAuthBootstrapError {
    fn from(error: PostgresAuthStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<PostgresTotpMethodError> for PostgresAuthBootstrapError {
    fn from(error: PostgresTotpMethodError) -> Self {
        Self::Totp(error)
    }
}

impl From<MountedAuthRuntimeError> for PostgresAuthBootstrapError {
    fn from(error: MountedAuthRuntimeError) -> Self {
        Self::MountedRuntime(error)
    }
}
