use super::*;

use std::sync::atomic::{AtomicU64, Ordering};

use crate::db::{
    PgIdentifier, PgSchemaName, Pool, PoolConfig, pooler_safe_query, unparameterized_simple_query,
};
use secrecy::SecretString;

static AUTH_POSTGRES_TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn postgres_store_persists_stable_wire_mappings() {
    assert_eq!(
        super::super::postgres_store::i32_from_proof_family(ProofFamily::OutOfBandCode),
        1
    );
    assert_eq!(
        super::super::postgres_store::proof_family_from_i32(7).expect("recovery code"),
        ProofFamily::RecoveryCode
    );
    assert!(
        super::super::postgres_store::proof_family_from_i32(0).is_err(),
        "invalid stored proof-family ids must not be accepted"
    );

    assert_eq!(
        super::super::postgres_store::i32_from_proof_use(ProofUse::BindSubjectToActiveProofAttempt),
        1
    );
    assert_eq!(
        super::super::postgres_store::proof_use_from_i32(7).expect("recover or replace"),
        ProofUse::RecoverOrReplaceCredential
    );
    assert!(
        super::super::postgres_store::proof_use_from_i32(8).is_err(),
        "invalid stored proof-use ids must not be accepted"
    );
}

#[test]
fn credential_secret_macs_are_bound_to_storage_target() {
    let keyset = test_keyset("tests.auth.postgres-store.secret-macs.v1");
    let secret = AuthCredentialSecret::try_from(b"session-secret".as_slice()).expect("secret");
    let session_one_target = CoreStorageTarget::SessionCredentialSecret {
        session_id: id("session-one"),
        secret_version: version(1),
    };
    let session_two_target = CoreStorageTarget::SessionCredentialSecret {
        session_id: id("session-two"),
        secret_version: version(1),
    };
    let mac = secret
        .to_mac(
            &keyset,
            &super::super::postgres_store::credential_secret_mac_context(&session_one_target),
        )
        .expect("mac");

    assert!(mac.verify(
        &keyset,
        secret.expose_secret(),
        &super::super::postgres_store::credential_secret_mac_context(&session_one_target),
    ));
    assert!(
        !mac.verify(
            &keyset,
            secret.expose_secret(),
            &super::super::postgres_store::credential_secret_mac_context(&session_two_target),
        ),
        "credential MACs must not verify when copied to a different target"
    );
}

#[tokio::test]
async fn postgres_store_migrates_and_validates_schema_when_database_is_available() {
    let Some(database_url) = std::env::var("PARANOID_TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DSN")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
    else {
        eprintln!(
            "skipping auth Postgres store test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

    let pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let schema_name = unique_test_schema_name();
    let schema = PgSchemaName::new(schema_name.clone());
    let create_schema = format!("CREATE SCHEMA {}", schema_name.quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(create_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("create auth test schema");

    let store_config = super::super::postgres_store::PostgresAuthStoreConfig::new(
        Some(schema.clone()),
        PgIdentifier::new("__paranoid_auth_").expect("table prefix"),
    )
    .expect("store config");
    let store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-store.credentials.v1"),
    );

    store
        .migrate_schema(&pool)
        .await
        .expect("migrate auth schema");
    store
        .validate_schema(&pool)
        .await
        .expect("validate migrated auth schema");

    pooler_safe_query(
        r#"DELETE FROM "__paranoid_schema_ledger" WHERE component = $1 AND instance_key = $2"#,
    )
    .bind("auth_core")
    .bind(super::super::postgres_store::schema_instance_key(
        &store_config,
    ))
    .execute(pool.sqlx_pool())
    .await
    .expect("remove schema ledger row");
    store
        .validate_schema(&pool)
        .await
        .expect_err("auth schema validation must require its schema ledger row");

    let drop_schema = format!("DROP SCHEMA {} CASCADE", schema.identifier().quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop auth test schema");
}

fn unique_test_schema_name() -> PgIdentifier {
    let counter = AUTH_POSTGRES_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    PgIdentifier::new(format!(
        "__paranoid_auth_test_{}_{}",
        std::process::id(),
        counter
    ))
    .expect("test schema name")
}

fn test_keyset(purpose: &str) -> crate::crypto::Keyset {
    let key =
        crate::crypto::Key32::try_from([29_u8; crate::crypto::KEY32_SIZE].as_slice()).expect("key");
    crate::crypto::derive_keyset_from_latest_first_keys([key], purpose).expect("keyset")
}
