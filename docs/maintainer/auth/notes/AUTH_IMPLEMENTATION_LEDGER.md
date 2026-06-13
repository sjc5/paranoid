# Auth Implementation Ledger

This ledger records findings from auditing the live auth implementation. It is not the
design source of truth and not a second roadmap. Use `AUTH_DESIGN.md` for intended auth
semantics, `AUTH_ROADMAP.md` for ordered work, and `AUTH_OPEN_QUESTIONS.md` for decisions
that need maintainer input.

Keep this file current while working on auth. Do not rely on memory across compaction.

## Current Audit Position

Auth is architecturally coherent, but not yet elegant.

The broad machine makes sense: lower-core planner, runtime-owned cookies and secrets,
database-authoritative positive auth, method plugins, Postgres runtime, mounted HTTP/Tower
surface, durable Queue effects, credential lifecycle policy, recovery-authority metadata,
and fast-fail gates. That is a real design, not random accumulation.

The current implementation shape is too large and concentrated to be release-quality as
written. The largest files are carrying too many responsibilities, and the tests preserve
valuable semantics in forms that are difficult to audit quickly. The work ahead should not
add another layer of feature sprawl. The private WIP mounted backend facade is now the
bootstrap-facing organizing root. `PostgresAuthSystemConfig` is now the private WIP
one-config root for the Postgres mounted product shape: DB bootstrap schema, credential
secret keyset, mounted runtime config, weak gates, web transport, first-party method
setup, route setup, mount path, and durable integrations live on one configuration object.
The remaining cleanup should split or delete private scaffolding beneath that facade.

Backend Rust auth readiness remains about 70%. That estimate reflects substantial
implemented behavior, not polish. It excludes client WASM/TypeScript and public docs, but
includes the Rust backend auth system needed for public alpha.

## Re-Grounding Snapshot

Snapshot date: 2026-06-11.

Commands run for this snapshot:

- `cargo fmt`
- `cargo check --features __auth_wip`
- `cargo check --features __auth_wip --tests`

Both auth feature checks pass after removing broad unused-import hiding and retaining only
a deliberate private-WIP `dead_code` allowance on the feature-gated private auth module
declaration in `src/lib.rs`.

Approximate live auth size from `wc -l`:

- `src/auth_core`: 136k lines including tests.
- `src/auth_core/mod.rs`: 261 lines; it is now a module/reducer root rather than a
  catch-all private prelude.
- `src/auth_core/prelude.rs`: 102 lines; it is an auth-core-private import surface for WIP
  internals and direct child modules.
- `src/auth_core/tests/postgres_runtime.rs`: about 5k lines of shared Postgres runtime
  test harness/helpers, plus behavior-family test modules under
  `src/auth_core/tests/postgres_runtime/`.
- `src/auth_core/postgres_runtime.rs`: about 1.1k lines plus transition-family modules
  under `src/auth_core/postgres_runtime/`.
- `src/auth_core/mounted_runtime_model.rs`: a small module root; the mounted runtime
  family is split across config, services, manifest, route guarding, route execution,
  route types, body parsing, response rendering, protected layers, and HTTP service
  modules.
- `src/auth_core/postgres_store.rs`: small module root, with Postgres store
  responsibilities split under `src/auth_core/postgres_store/`. The largest store-family
  modules are now mutation execution, precondition enforcement, row reads, load paths,
  schema validation, row writes, and value conversion.
- `src/auth_core/mounted_credential_lifecycle_model.rs`: 3.6k lines.
- `src/auth_core/tests/credential_lifecycle.rs`: 4.4k lines.
- `src/auth_core/tests/mounted_runtime.rs`: 3.6k lines.

## What Looks Sound

- The design center is still intact: fail fast, never succeed fast. Stateless material is
  used as rejection material, not as positive auth authority.
- Positive auth remains database-authoritative except for the explicitly bounded safe-read
  path.
- The lower-core planner is I/O-free and emits commit work plus response effects instead
  of performing side effects directly.
- Runtime-facing paths increasingly derive sensitive facts internally: fresh ids,
  continuation handles, CSRF checks, method work, lifecycle authority, pending-action
  records, and response cookies.
- The private mounted system exists and is conceptually aligned with the desired product:
  a framework-neutral mounted auth route service, protected-route layers, app subject
  mapping layer, route manifest, durable-effect worker, and bootstrap facade.
- First-party backend method coverage is not just sketches anymore. Email OTP, TOTP,
  recovery-code, and password-derived signature paths all have real backend method code
  and substantial Postgres/mounted coverage.
- Durable effects are flowing through Queue rather than after-commit callback convention.
- Schema and byte/collation posture have meaningful validation work in place.
- Operation-count and no-storage-work testing exists for many important paths.

## What Does Not Look Good Enough Yet

- Auth still has a private-WIP `dead_code` allowance because the `__auth_wip` module is
  intentionally not public. The allowance is now at the feature-gated module declaration
  in `src/lib.rs`, not inside `src/auth_core/mod.rs`. It must go before public auth
  exposure.

## Open Implementation Findings

- [ ] AUTH-IMPLEMENTATION-010: Privacy/enumeration coverage through the mounted backend
      surface is not finished. Existing coverage proves several important
      indistinguishable response paths, but the public mounted surface needs a final
      enumeration-resistance pass.

## Closed Implementation Findings

- [x] AUTH-IMPLEMENTATION-001: The private WIP mounted backend facade is now the
      bootstrap-facing organizing root. `AuthSystemConfig` owns the high-level configured
      auth surface, `PostgresAuthBootstrap` now builds a `PostgresAuthSystem` from that
      config, and the bootstrapped system exposes the route manifest, framework-neutral
      route service, protected-route layers, application-subject mapping layer, and
      durable-effect worker through that facade. Lower mounted config/runtime pieces still
      exist as private scaffolding and are tracked by the remaining module-splitting
      findings.
- [x] AUTH-IMPLEMENTATION-002: The mounted runtime model is now split by responsibility.
      `mounted_runtime_model.rs` is a small module root. The family now has separate
      modules for system config, system services, route manifest, route guarding, route
      execution, route types, collected-body parsing, response rendering, protected
      layers, HTTP service plumbing, and route/service errors. The split preserved the
      existing mounted service behavior and compiles with
      `cargo check --features __auth_wip --tests`.
- [x] AUTH-IMPLEMENTATION-003: The Postgres runtime is now split by transition family.
      `postgres_runtime.rs` keeps the runtime struct, shared transaction helpers,
      rollback/error conversions, and common execution plumbing. Request/session/device,
      active-proof challenge and response paths, credential read/addition, credential
      reset, credential replacement/removal, credential regeneration/rotation, pending
      credential lifecycle, subject lifecycle, and admin/support paths live in focused
      modules under `src/auth_core/postgres_runtime/`. The split preserved the existing
      runtime behavior and compiles with `cargo check --features __auth_wip --tests`.
- [x] AUTH-IMPLEMENTATION-004: The Postgres store is now split by responsibility.
      `postgres_store.rs` keeps the store struct, constructor/accessors, module wiring,
      and durable-effect kind constants. Focused modules under
      `src/auth_core/postgres_store/` now own config/table-name resolution, errors,
      transaction finishing, schema migration/validation, high-level load paths, row
      reads, row writes, precondition enforcement, mutation execution, method commit
      execution, credential-secret classification, value conversion, query helpers, and
      test-only seed helpers. The split preserved behavior and compiles with
      `cargo check --features __auth_wip --tests`.
- [x] AUTH-IMPLEMENTATION-005: The Postgres runtime test surface is now split by behavior
      family. `tests/postgres_runtime.rs` keeps shared harness, fixtures, helpers, and
      operation-observer assertions. Actual test functions now live under
      `tests/postgres_runtime/` in focused modules for bootstrap/schema, mounted recovery
      routes, message-signature methods, TOTP, recovery codes, active-proof guards,
      admin/support, mounted credential/subject routes, credential lifecycle planning and
      execution, unauthenticated recovery reset, subject lifecycle, out-of-band identifier
      changes, session/device request resolution, revocation/stale commits, durable
      effects, and method-work atomicity. The split preserved all 199 test attributes and
      compiles with `cargo check --features __auth_wip --tests`.
- [x] AUTH-IMPLEMENTATION-006: `auth_core/mod.rs` is no longer a giant private prelude.
      The root now declares modules, imports an auth-core-private `prelude` only for the
      reducer/root helpers, and keeps the reducer entry point plus its local transition
      and audit constructors. Direct production child modules import `super::prelude::*`
      instead of `super::*`, and the few root-local helpers are imported by explicit name
      where needed. The broad `dead_code` allowance was removed from
      `src/auth_core/mod.rs`; while auth remains private WIP, the unavoidable
      private-module dead-code allowance now lives only on the feature-gated auth module
      declaration in `src/lib.rs`. `cargo check --features __auth_wip --tests` compiles
      without warnings after the split.
- [x] AUTH-IMPLEMENTATION-007: `AUTH_ROADMAP.md` no longer carries long "current closure"
      implementation-history paragraphs inside checklist items. The roadmap now states its
      role as deliverables plus exit criteria, points detailed semantics/status to
      `AUTH_DESIGN.md` and this ledger, gives Phase 2/6/7 explicit exit criteria, and uses
      shared public-mounted lifecycle route criteria instead of repeating private route
      status under every route-family item.
- [x] AUTH-IMPLEMENTATION-008: `AUTH_DESIGN.md` now classifies every fast-fail matrix row
      with executable status and named test evidence. The table distinguishes fully pinned
      current paths, modeled-only future protocol families, and current private WIP
      mounted route/runtime paths. A missing no-storage assertion for trusted-device
      active-revival proof start was added as
      `postgres_runtime_current_trusted_device_active_proof_start_without_device_does_not_write`.
- [x] AUTH-IMPLEMENTATION-009: Auth schema/migration confidence is closed for the current
      public-alpha table set. Core auth tables are centralized in
      `PostgresAuthCoreSchemaContract`, first-party method tables are validated through
      the method registry, and the bootstrap/schema PgBouncer tests now assert the exact
      schema-local core plus email OTP, TOTP, recovery-code, and password-derived
      signature table set. The closure also pins physical validation before schema-ledger
      trust for both core and method-owned adopted tables, revalidation of recorded schema
      state, and the recorded v3-to-v4 auth schema upgrade path.
- [x] AUTH-IMPLEMENTATION-011: PgBouncer transaction-mode coverage is closed for current
      production auth storage entry points. The PgBouncer-backed Postgres runtime suite
      now references every production async storage entry point across direct runtime,
      mounted route/service helpers, durable-effect dispatch, durable-effect workers, and
      bootstrap/migration paths. The final explicit gaps were the direct authenticated
      credential-inventory runtime path and the mounted admin/support approval and denial
      staff-verification snapshot reads.
- [x] AUTH-IMPLEMENTATION-012: Exact operation-count coverage is closed for current
      public-alpha hot auth paths. The PgBouncer-backed Postgres runtime tests now pin
      ordered database-operation labels for direct runtime hot paths, mounted
      full-authentication, mounted credential addition/inventory/mutation routes, mounted
      admin/support request/approval/denial/expiry routes, mounted delayed credential
      execution, mounted out-of-band identifier-change routes, mounted subject-auth-state
      deletion routes, durable-effect dispatch, and Queue-backed delivery workers.
      Route-level tests now include intentional read-only preflight transactions where
      mounted services need snapshots for staff authorization or action dispatch, so those
      reads are explicit rather than hidden route overhead.

## Areas That Need Continued Audit

- Public mounted backend facade: decide the exact public names and shape, then make the
  private mounted system serve that shape instead of remaining a large internal toolkit.
  The current private foothold is `PostgresAuthSystemConfig` feeding `PostgresAuthSystem`.
  Mounted runtime construction now validates method capabilities for configured route
  families, so an advertised route cannot be backed merely by "some method registry" or by
  a registered method that lacks the exact work the route needs. Mounted route guarding
  now starts from the config-derived route manifest descriptor, so route existence, CSRF
  requirement, guarded-route construction, and HTTP body limits share one private source
  of truth instead of separate path-family walks. Protected app-route middleware now
  starts from `MountedAuthProtectedRoutePolicy`, so combined protected-route and protected
  application-subject mapping layers pair request kind with required auth posture through
  named constructors instead of loose route-code parameters.
- Fast-fail matrix: keep the matrix updated as new auth routes or method plugins are
  built, and do not claim no-storage or bounded-storage behavior until a focused test pins
  it.
- Privacy/enumeration: finish mounted-surface tests for indistinguishable responses where
  policy requires them.
- Public route rendering: collapse internal route response bodies into the final public
  response vocabulary. Current private foothold: the mounted HTTP renderer now emits JSON
  `type` values from one explicit public-shaped response-kind enum, and focused tests
  assert the response vocabulary is unique, public-shaped, and covers the rendered
  full-authentication, recovery, credential lifecycle, identifier-change, subject
  deletion, and admin/support outcomes. Authenticated credential inventory and the
  authenticated lifecycle mutation routes now share one mounted handle vocabulary:
  inventory emits `credential_handle_base64url`, and reset, replacement, removal,
  regeneration, and rotation route bodies consume that same field instead of exposing a
  credential-instance-id field. The mounted HTTP service now reaches route execution
  through a rendered-response boundary, so HTTP route code receives `Response<Vec<u8>>`
  with committed `Set-Cookie` headers instead of handling typed lower route bodies or
  calling the cookie/body renderer directly. The lower route service and aggregate route
  response body are private to the mounted runtime modules. Full-authentication
  out-of-band proof submission now has a dedicated route projection for committed
  proof-accepted/proof-rejected outcomes and pre-state fast-fail rejection, so endpoint
  dispatch no longer translates lower proof-verification errors inline.
- Adversarial lifecycle suite: build the realistic mounted application lifecycle suite.
  Existing tests are extensive but still mostly subsystem-shaped.
- File/module organization: split large files by responsibility only after the public
  facade is clear enough to avoid rearranging around the wrong center.

## Module-Family Ledger

### Lower Core Planner

Files include `command_model.rs`, `credential_lifecycle.rs`, `session_lifecycle.rs`,
`session_resolution.rs`, `session_revocation.rs`, `proof_policy.rs`,
`credential_model.rs`, `storage_contract_model.rs`, and commit-model files.

Assessment: coherent. The lower-core planner still matches the intended model: reduce
loaded state plus command into transition plan. The main risk is not conceptual drift; it
is that public runtime paths must keep refusing direct access to low-level commands that
require runtime-owned facts.

Recorded follow-up: keep direct-command rejection tests aligned with every new mounted or
runtime facade.

### Runtime Orchestration

Files include `runtime_orchestration_model.rs`, `runtime_adapter_model.rs`,
`response_materialization_model.rs`, `web_transport_model.rs`, and
`challenge_cookie_model.rs`.

Assessment: coherent and mostly shaped correctly. Runtime owns cookie decode/encode, fresh
secret materialization, response-effect projection, and CSRF hooks. The remaining concern
is exposure: public APIs should not leak the lower orchestration pieces as user surface.

Recorded follow-up: public facade should expose mounted services/layers, not these lower
pieces.

### Postgres Runtime

Primary files: `postgres_runtime.rs` plus transition-family modules under
`postgres_runtime/`.

Assessment: semantically important and now split into auditable transition families. The
root file keeps shared runtime structure, rollback conversions, transaction helpers, and
common execution plumbing. Request/session/device, active-proof challenge and response,
credential lifecycle, subject lifecycle, and admin/support paths now sit in separate
modules. The remaining risk in this family is not the root file size; it is keeping future
runtime additions inside the correct transition-family module instead of letting the root
file grow back into an orchestrator pile.

Recorded follow-up: keep shared transaction helpers in the root and add new runtime paths
to the narrowest matching transition-family module.

### Postgres Store And Schema

Primary files: `postgres_store.rs`, modules under `postgres_store/`,
`postgres_schema_model.rs`, `postgres_adapter_execution_model.rs`,
`postgres_method_schema.rs`.

Assessment: substantially built and now split into smaller audit units. The schema catalog
and validation work remain a good direction. Future store changes should land in the
narrow matching module rather than growing the root store file back into a mixed
orchestrator.

Recorded follow-up: keep final-alpha schema/migration closure focused on table-family
completeness and validation coverage, not on file shape.

### First-Party Methods

Files include `email_otp_method.rs`, `postgres_totp_method.rs`,
`postgres_recovery_code_method.rs`, and `postgres_password_derived_signature_method.rs`.

Assessment: real backend plugins exist and appear aligned with the method-contract model.
These files are large but not absurd relative to their responsibilities. Their risk is
less size and more ensuring every method-owned schema, fast-fail boundary, durable effect,
and lifecycle mutation remains registered through the method contract rather than special
cases.

Recorded follow-up: finish public-alpha method audit after the mounted public facade is
chosen; do not add post-alpha method implementations until alpha surface is stable.

### Mounted Runtime And HTTP Surface

Primary files: `mounted_runtime_model.rs`, `mounted_credential_lifecycle_model.rs`,
`mounted_credential_lifecycle_service.rs`, `mounted_subject_lifecycle_model.rs`,
`mounted_subject_lifecycle_service.rs`, `mounted_admin_support_model.rs`,
`mounted_admin_support_service.rs`, and `mounted_durable_effect_worker_service.rs`.

Assessment: the right public-product idea exists privately, and the mounted runtime model
is now split into smaller responsibility modules around that idea. The remaining concern
is public exposure and final product vocabulary, not a single giant mounted-runtime file.

Recorded follow-up: design/export the public mounted backend facade before adding more
route families.

### Tests

Primary large files include `tests/credential_lifecycle.rs`, `tests/mounted_runtime.rs`,
`tests/storage_contract.rs`, and the shared-helper root plus behavior-family modules under
`tests/postgres_runtime/`.

Assessment: coverage is extensive and valuable. The Postgres runtime coverage is now much
more auditable because behavior-family modules keep runtime assertions close to the
families they protect while sharing one harness.

Recorded follow-up: keep new Postgres runtime tests in the matching behavior-family module
and keep operation-count assertions near the runtime family they protect.

## Working Rule From This Audit

Until this ledger says otherwise, do not continue auth by adding more low-level feature
surface. The next implementation work should make the public mounted backend facade the
center of gravity, then use that facade to remove, split, or hide private scaffolding.
