# Component Schema Migrations

Paranoid's DB foundation exposes a generic component-schema ledger for Postgres table
families owned by Paranoid subsystems, downstream crates, or applications.

The API is intentionally small:

- a component declares its current version, fingerprint, fresh-install SQL, ordered
  upgrade SQL, and physical validation SQL;
- callers provide a validated schema-ledger table name;
- migration runs inside an existing `db::WriteTx`;
- validation runs inside an existing `db::Tx`;
- ledger state is recorded only after the selected physical SQL and validation SQL
  succeed.

This is not a general migration framework. It has no CLI, file discovery, down migrations,
or application lifecycle policy. It exists to make the safe path boring: fresh install,
already-current validation, and ordered upgrades with fingerprint mismatch detection.

Ledger tables and component tables may live in any Postgres schema. Public APIs use
`db::PgQualifiedTableName` for every table name. Schema instance keys use validated
`db::PgIdentifier` labels plus quoted qualified table names, so two schemas with the same
table names remain distinct without accepting ambiguous label strings.

The migration helper must preserve the same DB invariants as Paranoid internals:

- Postgres only;
- transaction-pooler safe;
- no session-level state;
- simple-query protocol for unparameterized DDL;
- byte-stable schema ledger text through `TEXT COLLATE "C"`;
- loud failure for stale versions, future versions, fingerprint mismatch, and physical
  validation drift.

Do not expose lower-level ledger recording as the public API. Recording a version without
first validating the physical schema is the exact footgun this helper exists to remove.
