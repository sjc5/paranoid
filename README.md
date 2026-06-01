# Paranoid

<img src="paranoid-banner.webp" alt="Paranoid banner">

Paranoid is a library of misuse-resistant application security and distributed systems
primitives.

---

**WARNING:** Paranoid is in an alpha state, and it has not undergone a formal security
audit. Use at your own risk. There will be frequent breaking changes, so be sure to pin to
a specific version.

---

This crate is organized as a small set of intention-revealing namespaces:

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
paranoid = { version = "0.X.Y", features = ["crypto"] }
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

Paranoid constructs its SQLx pools through its own configuration path so the internal
portability guarantees stay under library control. `paranoid::db::Pool` and
`paranoid::db::Tx` are neutral DB handles; they do not imply particular database
privileges. `paranoid::db::WritePool` and `paranoid::db::WriteTx` are marker wrappers used
by Paranoid APIs whose existing behavior requires write authority. These marker wrappers
do not inspect, reduce, or enforce Postgres privileges. Construct each pool with the
connection URL and database role intended for that call site.

Applications may use the exposed SQLx pool and active transaction accessors for app-owned
tables and queries. App-owned SQL may use raw SQLx normally. When an application wants its
own SQL to follow Paranoid's portable execution style, it can use
`paranoid::db::portable_query`, `paranoid::db::portable_query_as`, or
`paranoid::db::portable_query_scalar` inside an explicit Paranoid transaction.
