# Paranoid

**Warning:**

_Paranoid is in an alpha state and has not undergone a formal security audit. Use at your
own risk and discretion, and understand that there will be frequent breaking changes for
the foreseeable future._

<img src="paranoid-banner.webp" alt="Paranoid banner">

Paranoid is a library of misuse-resistant application security and Postgres-driven
distributed systems primitives. It currently consists of a single Rust crate called
`paranoid`, but in the future there will be a client-side TypeScript element as well.

## Reason To Exist

Paranoid's aim is to provide a high-level, wide-ranging (yet cohesive) toolkit with secure
defaults covering all the hard, boring parts of application development. Where persistence
is required, Paranoid is built on a single (connection-pooler-safe) Postgres substrate.

AI and quantum advances have made having a "paranoid" attitude toward application security
all but required, and advances in Postgres hosting such as Planetscale Metal have made
Redis-less architectures an increasingly valid option. Further, serverless and
container-based deployments make cross-instance coordination more important than ever.

Paranoid exists to fill these gaps in the market.

## Package Shape

Default features are disabled. Enable only the namespaces your crate uses.

```toml
[dependencies]
paranoid = { version = "0.0.0-pre.10", features = ["db"] }
```

Available feature groups:

- `crypto`: typed encryption envelopes, keysets, password-sealed keys (stored-salt and
  caller-salt shapes), MACs over secret bytes, Ed25519 signatures, an ML-KEM-768
  post-quantum key encapsulation primitive, edge codecs, and byte-container primitives
- `id`: human-friendly, aesthetically pleasing k-sortable timestamped IDs and pure-random
  ASCII IDs
- `web`: encrypted secure cookies and CSRF helpers
- `local-lock`: local process file locks with heartbeat-based stale recovery
- `local-env-vault`: local encrypted env vaults and command runners (to prevent agents
  from reading secrets in .env files)
- `db`: SQLx/Postgres pool wrappers plus KV, Fleet, and Queue
- `db-test-harness`: isolated embedded Postgres plus pinned transaction-mode PgBouncer
  test harness for crates and applications

Public modules follow those features:

- `paranoid::crypto`
- `paranoid::id`
- `paranoid::web`
- `paranoid::local_lock`
- `paranoid::local_env_vault`
- `paranoid::db`
- `paranoid::kv`
- `paranoid::fleet`
- `paranoid::queue`

## Crypto

`crypto` provides typed encryption envelopes and associated-data binding. The caller
chooses the domain string once when deriving a keyset, then each encryption operation
binds ciphertext to a local context such as a cookie name, vault entry, or protocol field.

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct SessionPayload {
    user_id: String,
}

fn encrypt_session() -> Result<(), paranoid::crypto::Error> {
    let current_key = paranoid::crypto::random_key32()?;
    let keyset = paranoid::crypto::derive_keyset_from_latest_first_keys(
        [current_key],
        "my-app.sessions.v1",
    )?;

    let payload = SessionPayload {
        user_id: "user_123".to_owned(),
    };
    let encrypted = paranoid::crypto::encrypt(&keyset, &payload, b"session-cookie")?;
    let decrypted: SessionPayload =
        paranoid::crypto::decrypt(&keyset, &encrypted, b"session-cookie")?;

    assert_eq!(decrypted, payload);
    Ok(())
}
```

For bearer-style material, store a MAC over the secret rather than the secret itself:

```rust
fn mac_secret() -> Result<(), paranoid::crypto::Error> {
    let keyset = paranoid::crypto::derive_keyset_from_latest_first_keys(
        [paranoid::crypto::random_key32()?],
        "my-app.tokens.v1",
    )?;
    let secret = paranoid::crypto::random_secret_bytes(32)?;
    let mac = secret.to_mac(&keyset, b"api-token")?;

    assert!(mac.verify(&keyset, secret.expose_secret(), b"api-token"));
    Ok(())
}
```

For asymmetric signatures, `crypto` exposes a raw Ed25519 primitive (RFC 8032) over a
32-byte seed:

```rust
fn sign_and_verify() -> Result<(), paranoid::crypto::Error> {
    let seed = paranoid::crypto::random_key32()?;
    let key_pair = paranoid::crypto::Ed25519KeyPair::from_seed(&seed);
    let public_key = key_pair.public_key();

    let signature = key_pair.sign(b"canonical message bytes");
    assert!(public_key.verify(b"canonical message bytes", &signature).is_ok());
    Ok(())
}
```

For key encapsulation, `crypto` exposes a raw ML-KEM-768 primitive (FIPS 203), Paranoid's
only post-quantum asymmetric primitive and its only public-key encryption/KEM of any kind.
An encapsulator holding only the recipient's public encapsulation key establishes a shared
32-byte secret with the holder of the matching decapsulation key:

```rust
fn encapsulate_and_decapsulate() -> Result<(), paranoid::crypto::Error> {
    let seed = paranoid::crypto::MlKem768Seed::generate()?;
    let decapsulation_key = paranoid::crypto::MlKem768DecapsulationKey::from_seed(&seed);
    let encapsulation_key = decapsulation_key.encapsulation_key();

    let (ciphertext, sender_secret) = encapsulation_key.encapsulate()?;
    let receiver_secret = decapsulation_key.decapsulate(&ciphertext);

    assert_eq!(sender_secret, receiver_secret);
    Ok(())
}
```

For sealing a 32-byte key at rest under a password, `crypto` provides two mutually
exclusive record shapes: a stored-salt shape that generates and carries its own Argon2id
salt, and a caller-salt shape that never generates or stores a salt, so the caller must
supply the exact same secret salt back on open (for example, a second independently held
factor):

```rust
use paranoid::crypto::{PasswordKdfParams, SecretBytes};

fn fill_random(buf: &mut [u8]) -> Result<(), paranoid::crypto::Error> {
    let random = paranoid::crypto::random_secret_bytes(buf.len())?;
    buf.copy_from_slice(random.expose_secret());
    Ok(())
}

fn seal_and_open_password_key() -> Result<(), paranoid::crypto::Error> {
    let key = paranoid::crypto::random_key32()?;
    let password: SecretBytes = SecretBytes::try_from(b"correct horse battery staple".as_slice())?;
    let params = PasswordKdfParams::interactive_default();

    // Stored-salt shape: the salt is generated here and travels inside the record.
    let stored_salt_record =
        paranoid::crypto::seal_key32_with_password(&key, &password, params, fill_random)?;
    let opened = paranoid::crypto::open_key32_with_password(&stored_salt_record, &password)?;
    assert_eq!(opened.expose_secret(), key.expose_secret());

    // Caller-salt shape: the caller holds the salt out of band and supplies it on open.
    let caller_salt = paranoid::crypto::random_key32()?;
    let caller_salt_record = paranoid::crypto::seal_key32_with_password_and_caller_salt(
        &key,
        &password,
        &caller_salt,
        params,
        fill_random,
    )?;
    let opened = paranoid::crypto::open_key32_with_password_and_caller_salt(
        &caller_salt_record,
        &password,
        &caller_salt,
    )?;
    assert_eq!(opened.expose_secret(), key.expose_secret());
    Ok(())
}
```

## IDs

`id` has two intentionally separate shapes:

- `SortableId`: 16 bytes that sort by creation time in byte form, with 76 bits of
  cryptographic randomness behind a 52-bit timestamp
- `RandomId`: pure entropy rendered as lowercase or anycase ASCII alphanumerics

```rust
fn ids() -> Result<(), paranoid::id::Error> {
    let sortable = paranoid::id::SortableId::new()?;
    let text = sortable.to_text();
    let parsed = paranoid::id::SortableId::parse(&text)?;
    assert_eq!(parsed.as_bytes(), sortable.as_bytes());

    let public_id = paranoid::id::RandomId::alphanumeric_lowercase(24)?;
    assert_eq!(public_id.len(), 24);
    Ok(())
}
```

The human-facing text representation of `SortableId` XORs the timestamp bytes with the
random entropy so that different ids appear obviously different to human observers. This
can be helpful when scanning logs or rows of data, as each id looks different at the
beginning of the string, not just the end.

## Web

`web` provides encrypted `__Host-` secure cookies and CSRF helpers. It owns the cookie
serialization/encryption boundary so applications do not hand-assemble security-sensitive
cookie strings.

```rust
fn cookie() -> Result<(), Box<dyn std::error::Error>> {
    let keyset = paranoid::crypto::derive_keyset_from_latest_first_keys(
        [paranoid::crypto::random_key32()?],
        "my-app.cookies.v1",
    )?;
    let cookies = paranoid::web::CookieManager::from_keyset(keyset);
    let session_cookie =
        cookies.secure_cookie::<String>(paranoid::web::SecureCookieConfig::new("session"))?;

    let cookie = session_cookie.new_cookie(&"session-id".to_owned())?;
    assert!(cookie.name().starts_with("__Host-"));
    Ok(())
}
```

## Postgres Bootstrap

The `db` feature is Postgres-only and SQLx-backed. Paranoid owns pool construction so its
internal queries use conservative connection settings, including transaction-pooler-safe
prepared-statement behavior.

Paranoid's blessed DB setup path is to own one dedicated schema. The application must
choose that schema name explicitly. The examples below use `__paranoid`, but Paranoid does
not silently pick a schema for the application.

```rust,no_run
use paranoid::db::{BootstrapConfig, PoolConfig, WritePool};
use paranoid::kv::{Key, Ttl};
use paranoid::queue::EnqueueOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = secrecy::SecretString::from(std::env::var("DATABASE_URL")?);
    let pool = WritePool::connect(PoolConfig::new(database_url)).await?;

    let stores = BootstrapConfig::from_schema_name_text("__paranoid")?
        .migrate_schema(&pool)
        .await?;

    let key = Key::from_parts(["account", "acct_123", "status"])?;
    stores
        .kv
        .set_bytes(&pool, &key, b"active", Ttl::no_expiration())
        .await?;

    stores
        .queue
        .enqueue_json(
            &pool,
            "billing.rollup.v1",
            &"acct_123",
            EnqueueOptions::default(),
        )
        .await?;

    Ok(())
}
```

Bootstrap binds KV, Fleet, and Queue to one installation protocol relation. The first
Paranoid operation in each transaction acquires a shared relation lock and checks the
active epoch and fingerprint. Admission is reused until transaction completion; borrowing
the raw SQLx transaction invalidates that cache because application SQL can roll back a
savepoint. Pool transactions explicitly use READ COMMITTED and READ WRITE, independently
of database defaults. SQL privileges still determine whether a role can write.

This Rust implementation supports epoch 1 (`paranoid.protocol.pre9-state.v1`) and
preserves its existing stored formats. Bootstrap also accepts the explicitly compatible
prepared Fleet v8 and Queue v2 layouts under epoch 1 without changing their schema ledger
records. An incompatible activation must hold the protocol relation exclusively, so it
waits for admitted transactions. Subsequent Rust operations return `db::ProtocolError`
before accessing Paranoid state. Queue workers stop after protocol rejection, and lease
guards lose authority when renewal detects it. Guards and callbacks do not retain a
database transaction throughout application work; applications must still observe their
existing cancellation and leadership-loss signals.

The protocol relation must exist before handles constructed for an already-migrated schema
can access state. Schema preparation and epoch activation are distinct operations; this
Rust implementation can prepare epoch-1 metadata but cannot activate another epoch. All
participating processes must enforce admission before an incompatible activation. The
unmodified `0.0.0-pre.9` release does not enforce it.

Application-owned SQL can share the Paranoid-created SQLx pool and transactions. If an
application wants its own queries to keep the same portable execution style
(transaction-pooler safety), it can use `paranoid::db::portable_query`,
`portable_query_as`, or `portable_query_scalar`.

Code that already bootstraps Paranoid can register additional schema families under the
same DB foundation. Paranoid owns the shared schema ledger, migration transaction, and
multi-process coordination. Callers provide only the schema family's stable identity,
fresh-install statements, ordered upgrade statements, and physical validation checks.
Validation checks must return boolean `true` before Paranoid records the version, and
dynamic SQL should be built only from validated Postgres identifiers.

```rust,no_run
# #[cfg(feature = "db")]
# async fn component_schema_example(
#     pool: &paranoid::db::WritePool,
# ) -> Result<(), Box<dyn std::error::Error>> {
use paranoid::db::{
    component_schema_instance_key_for_tables, AuditedSql, BootstrapConfig, ComponentSchema,
    ComponentSchemaStatement, ComponentSchemaValidationCheck, ComponentSchemaVersion,
    PgIdentifier, PgQualifiedTableName,
};

let pages_table = PgQualifiedTableName::with_schema("__app", "md_pages")?;
let pages_label = PgIdentifier::new("pages")?;
let instance_key = component_schema_instance_key_for_tables([(&pages_label, &pages_table)]);

let stores = BootstrapConfig::from_schema_name_text("__paranoid")?
    .migrate_schema(pool)
    .await?;
let install = [
    ComponentSchemaStatement::from_static_sql(r#"CREATE SCHEMA IF NOT EXISTS "__app""#)?,
    ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
        "CREATE TABLE {} (id BYTEA PRIMARY KEY, body BYTEA NOT NULL)",
        pages_table.quoted()
    )))?,
];
let validation = [ComponentSchemaValidationCheck::from_audited_dynamic_boolean_expression(
    AuditedSql::new(format!(
        "NOT EXISTS (SELECT id, body FROM {} WHERE false)",
        pages_table.quoted()
    )),
)?];
let schema = ComponentSchema::new(
    ComponentSchemaVersion {
        component: "cook.md_pages",
        instance_key: instance_key.as_str(),
        version: 1,
        fingerprint: "md-pages-v1",
    },
    &install,
    &[],
    &validation,
)?;

let _outcome = stores.migrate_component_schema(pool, &schema).await?;
# Ok(())
# }
```

With `db-test-harness`, crates and applications can run their own tests against the same
isolated embedded Postgres plus transaction-mode PgBouncer substrate Paranoid uses:

```rust,no_run
# #[cfg(feature = "db-test-harness")]
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let harness = paranoid::db::testing::IsolatedPostgresTestHarness::start().await?;
let pool = harness.connect_standard_write_pool().await?;

let stores = paranoid::db::BootstrapConfig::from_schema_name_text("__paranoid")?
    .migrate_schema(&pool)
    .await?;

stores.kv.set_bytes(
    &pool,
    &paranoid::kv::Key::from_parts(["test", "key"])?,
    b"value",
    paranoid::kv::Ttl::no_expiration(),
).await?;

harness.shutdown().await?;
# Ok(())
# }
```

## KV

`kv` is Postgres-backed keyed state with TTL-oriented operations. Use it for small,
durable, transactional state where Redis would often be reached for by habit: active
challenge state, idempotence records, cached computed values, small metadata records, and
other keyed state that benefits from Postgres atomicity and visibility.

```rust,no_run
# async fn example(pool: paranoid::db::WritePool) -> Result<(), Box<dyn std::error::Error>> {
let stores = paranoid::db::BootstrapConfig::from_schema_name_text("__paranoid")?
    .migrate_schema(&pool)
    .await?;
let key = paranoid::kv::Key::from_parts(["tenant", "t_123", "feature-flag"])?;

stores
    .kv
    .set_bytes(
        &pool,
        &key,
        b"enabled",
        paranoid::kv::Ttl::no_expiration(),
    )
    .await?;

let value = stores.kv.get_bytes(&pool, &key).await?;
assert_eq!(value.as_slice(), b"enabled");
# Ok(())
# }
```

## Fleet

`fleet` is the distributed coordination layer: mutexes, once-only tasks, cron leadership,
coalescing caches, topics, semaphores, throttlers, rate limiters, and circuit breakers. It
exposes high-level protocols first; lower-level manual protocols live under
`paranoid::fleet::manual`.

```rust,no_run
use std::time::Duration;

use paranoid::fleet::{ClaimDuration, MutexGuardConfig, MutexKey, MutexTryRunTaskResult};

# async fn example(pool: paranoid::db::WritePool) -> Result<(), Box<dyn std::error::Error>> {
let stores = paranoid::db::BootstrapConfig::from_schema_name_text("__paranoid")?
    .migrate_schema(&pool)
    .await?;
let mutex = stores.fleet.new_mutex(
    MutexKey::new("billing-rollup")?,
    ClaimDuration::expires_after(Duration::from_secs(30))?,
)?;

let result = mutex
    .try_run_task(&pool, MutexGuardConfig::default(), |_snapshot| async {
        Ok::<_, std::io::Error>("rolled-up")
    })
    .await?;

assert_eq!(result, MutexTryRunTaskResult::Ran("rolled-up"));
# Ok(())
# }
```

## Queue

`queue` is a durable Postgres-backed work queue. Task names are explicit stable protocol
strings, not reflection output. Enqueue APIs have transaction-scoped variants when work
must be scheduled atomically with app-owned state changes.

```rust,no_run
# async fn example(pool: paranoid::db::WritePool) -> Result<(), Box<dyn std::error::Error>> {
let stores = paranoid::db::BootstrapConfig::from_schema_name_text("__paranoid")?
    .migrate_schema(&pool)
    .await?;

let result = stores
    .queue
    .enqueue_json(
        &pool,
        "email.send_welcome.v1",
        &"user_123",
        paranoid::queue::EnqueueOptions::default(),
    )
    .await?;

assert!(!result.deduplicated);
# Ok(())
# }
```

## Local Operator Tools

`local_lock` is a heartbeat-backed process file lock for local tooling. It does not kill
other processes; stale recovery is based on the lock heartbeat.

`local_env_vault` is for application-owned wrappers such as `./env`. The application
defines profiles in code; Paranoid owns vault encryption, password prompting, file
locking, atomic writes, and child-process env projection. See
`playgrounds/local_env_vault` to get a feel for how this might be set up.

```rust,no_run
use paranoid::local_env_vault::{Profile, VaultRunner};

fn main() -> Result<(), paranoid::local_env_vault::Error> {
    let profiles = [
        Profile::new("app", ["DATABASE_URL", "APP_API_KEY"])?,
        Profile::new("worker", ["DATABASE_URL", "WORKER_MODE"])?,
    ];
    let mut runner = VaultRunner::new(env!("CARGO_MANIFEST_DIR"), ".", profiles)?;

    runner.run_from_args(std::env::args_os())
}
```

The wrapper command shape is intentionally small:

- `configure`
- `validate PROFILE`
- `run PROFILE -- COMMAND [ARG ...]`

Secrets are treated as sensitive by default and are not printed by the vault runner.

## Postgres Posture

Paranoid DB primitives are designed for Postgres and for transaction-mode connection
poolers. Internals avoid session-level state such as `LISTEN`/`NOTIFY` and session-scoped
advisory locks. The bootstrap migrator uses one transaction-scoped advisory lock before
Paranoid's own coordination tables exist, then the rest of the runtime coordination model
uses Paranoid's row-based primitives.

Internal persisted identifiers, secrets, MACs, hashes, ciphertext, job IDs, and similar
opaque material are stored with byte-stable semantics. Text that participates in
correctness-sensitive equality or ordering is validated and uses bytewise-compatible
Postgres collation.

## Status

Paranoid is currently pre-release software. The public primitives are intended to be
usable by early consumers who are comfortable with breaking changes.
