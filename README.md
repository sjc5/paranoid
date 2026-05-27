# Paranoid

**DISCLAIMER:** `paranoid` is in an alpha state, and it has not undergone a formal
security audit. Use at your own risk. Additionally, there will be frequent breaking
changes, so it is recomended to pin the package to a specific version.

`paranoid` is a Rust crate for misuse-resistant application security and Postgres-backed
distributed systems primitives. It is organized as a small set of intention-revealing
namespaces:

- `paranoid::crypto`: typed encryption, keysets, MACs over secret bytes, edge codecs, and
  byte-container primitives
- `paranoid::id`: sortable timestamped identifiers and pure-random text IDs
- `paranoid::local_lock`: local process file locks with heartbeat recovery
- `paranoid::local_env_vault`: local encrypted environment vault wrappers
- `paranoid::web`: secure cookies and CSRF helpers
- `paranoid::db`: Paranoid-owned SQLx/Postgres pool and transaction wrappers
- `paranoid::kv`: Postgres-backed keyed state with TTL-oriented operations
- `paranoid::fleet`: Postgres-backed coordination primitives
- `paranoid::queue`: Postgres-backed durable work queue

Default features are disabled. Consumers opt into the namespaces they use: `crypto`, `id`,
`local-lock`, `local-env-vault`, `web`, or `db`.

## Feature Selection

Enable only the namespaces your crate uses:

```toml
[dependencies]
paranoid = { version = "0.0.0-pre.1", features = ["crypto"] }
```

Feature groups compose intentionally:

- `crypto`: typed encryption, keysets, MACs, and edge codecs
- `id`: sortable and random IDs without the crypto stack
- `local-lock`: heartbeat-backed local process file locks
- `local-env-vault`: local encrypted env vaults, including `crypto` and `local-lock`
- `web`: cookies and CSRF helpers, including `crypto`
- `db`: Postgres-backed KV, Fleet, Queue, and SQLx wrappers, including `crypto` and `id`

## Postgres Posture

The database-backed surfaces are Postgres-only and are designed to remain compatible with
transaction-mode connection poolers. Paranoid internals do not depend on advisory locks,
`LISTEN`/`NOTIFY`, or any other Postgres behavior that requires session state to survive
across transactions.

Paranoid constructs its SQLx pool through its own configuration path so the internal
portability guarantees stay under library control. Applications may use the exposed SQLx
pool and active transaction accessors for app-owned tables and queries. App-owned SQL may
use raw SQLx normally. When an application wants its own SQL to follow Paranoid's portable
execution style, it can use `paranoid::db::portable_query`,
`paranoid::db::portable_query_as`, or `paranoid::db::portable_query_scalar` inside an
explicit Paranoid transaction.
