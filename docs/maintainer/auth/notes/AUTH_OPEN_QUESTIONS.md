# Auth Open Questions

This document tracks unresolved auth design questions. It is intentionally short. Resolved
decisions belong in `AUTH_DESIGN.md`, not here.

## Immediate Design Work

- Use the fast-fail transition matrix in `AUTH_DESIGN.md` as the checklist for new auth
  work. The matrix exists now; the remaining work is to close the gaps below and add tests
  that pin each row's pre-state gate and authoritative post-gate boundary.
- `AUTH_DESIGN.md` now states the final product shape: one robust configuration should
  produce the mounted Paranoid auth system, including middleware, endpoint handlers,
  cookies, CSRF, storage, durable effects, audit, first-party methods, and lifecycle
  policy. New lower-layer designs must be checked against that public shape so auth does
  not degrade into app-assembled ceremonies.
- `AUTH_DESIGN.md` now names credential lifecycle and recovery policy as a core layer, not
  application glue. Before implementing credential reset, email change, second-factor
  reset, account deletion, or admin/support recovery, design the concrete records,
  transition policies, independence checks, pending-action semantics, durable notices, and
  stale-commit guards.

## Health Recovery Ledger

This section is the running ledger for unhealthy auth model drift. Update it immediately
when a drift, contradiction, or suspicious boundary is found, before continuing analysis
or code edits.

- Current checkpoint: the recovery audit is now focused on finding remaining places where
  the runtime or tests can treat low-level facts as caller-provided instead of
  runtime/plugin-derived. Keep this section current before each fix so compaction cannot
  erase the reason for the next edit.
- The current design note now explicitly names the four settled auth layers: generic
  primitives, proof families, concrete plugins, and lifecycle/policy transitions. Do not
  let a single plugin method, such as password-derived signing, reshape the lower
  primitive or proof-family model. Message-signature fast-fail is a family-level
  challenge-response shape shared by password-derived, SSH, wallet, and similar methods.
- The method adapter contract model already expresses the agreed four-layer split:
  primitives, proof families, concrete plugins, and lifecycle/policy transitions. Do not
  redesign that split from scratch. Audit runtime and plugin execution against it.
- `MethodAdapterContract` says which responsibilities are pre-state and post-state for
  each proof family. The active-method Postgres runtime path now enforces pre-state
  verification before authoritative confirmation, and email OTP subject resolution now
  happens inside the post-gate transaction. Continue auditing every new plugin lane
  against the contract instead of assuming the registry shape is sufficient by itself.
- `ActiveProofMethodPreStateVerification` was tightened during this audit so the
  authoritative lane carries a pre-state verified proof as
  `AcceptedNeedsAuthoritativeConfirmation`. Continue auditing for similar loose "load
  first, verify later" states elsewhere.
- The Postgres runtime test plugin previously had an `AuthoritativeState` mode that
  returned "needs authoritative state" before producing a verified proof. That blessed
  DB-first active-method verification. The code now names that mode
  `AuthoritativeConfirmation` and requires the pre-state phase to produce the verified
  proof before state is loaded.
- The message-signature family should be described consistently as a family-level
  fast-fail case. Password-derived signatures, SSH signatures, wallet signatures, and
  similar plugins are concrete methods under the same family, not separate lower-core
  shapes.
- Online-guessing risk is currently carried on `ProofMethodDeclaration`. That is the
  correct abstraction for distinguishing password-derived signatures from high-entropy
  signatures inside the message-signature family, but it becomes a footgun if arbitrary
  application plugins can under-declare risk. First-party method declarations should be
  owned by Paranoid, and any future custom-plugin API must make risk declaration an
  explicit reviewed boundary rather than a casual constructor choice.
- `ProofMethodDeclaration` constructors should be crate-owned while auth is WIP. Tests and
  first-party plugins may declare methods internally, but no future public auth surface
  should accidentally expose casual method/risk constructors as the plugin API.
- `ProofMethodDeclaration` constructors are now `pub(crate)`. Future custom-method support
  should be designed as a reviewed registry boundary, not by widening those constructors.
- The current design note matrix now states active-method test plugins cover pre-state
  proof verification plus optional authoritative confirmation. Keep watching for wording
  that could regress this back into DB-first proof verification.
- Any test that blesses loading authoritative state before verifying a method's required
  pre-state proof must be rewritten or rejected. Tests should prove the semantic contract,
  not just the current runtime branch.
- The generic `AuthWebRuntime` path and the Postgres runtime path must be checked for
  divergence. If the generic path is merely a model/test scaffold, the notes and code
  should make that clear so it is not mistaken for the intended production runtime shape.
- The generic `AuthWebRuntime` path is internal today because `auth_core` is private. Its
  storage-adapter facade and execution result types have been tightened to `pub(crate)` so
  opening auth later does not accidentally expose a plugin-bypassing generic runtime
  surface.
- Runtime-owned fresh value generation has been tightened in the Postgres runtime.
  Semantic runtime inputs now generate fresh session IDs, trusted-device credential IDs,
  active-proof attempt IDs, and challenge IDs at the facade boundary before lowering into
  reducer commands. The reducer still receives those IDs as internal command material so
  storage preconditions remain explicit and testable.
- `PostgresAuthWebRuntime::execute_from_headers` now rejects direct runtime calls to
  lifecycle commands that carry runtime-owned fresh IDs. Direct reducer commands remain
  valid only inside reducer/storage-precondition tests, especially stale loaded-state
  commit tests that intentionally plan work inside an already-open transaction.
- Runtime-owned fresh ID generation is covered by the PgBouncer-backed Postgres runtime
  test filter:
  `cargo run --manifest-path xtask/Cargo.toml --quiet -- with-isolated-test-db -- cargo test --no-default-features --features auth postgres_runtime`.
  That run caught and fixed a stale helper that still counted proofs under an old
  caller-selected attempt ID.
- Generic `AuthWebRuntime` now mirrors the Postgres runtime-owned-ID boundary. Its
  semantic facades generate fresh IDs before lowering to reducer commands, direct
  lifecycle commands with fresh IDs are rejected, and challenge issue takes a
  runtime-facing input rather than a caller-selected challenge ID.
- Generic `AuthWebRuntime` now mirrors the Postgres runtime on the state-load boundary:
  no-load commands finish from presented-cookie state without calling the adapter, and
  loaded-state paths validate the loaded-state contract immediately after adapter load.
  `web_runtime` tests pin missing-auth request resolution and commit-only attempt start as
  no-load paths.
- The first-party email OTP plugin helper now returns the runtime-facing challenge issue
  input rather than the lower request shape with a caller-supplied challenge id. Future
  first-party plugin helpers should stay on semantic runtime-facing inputs, not reducer
  command material.
- Challenge completion now checks encrypted challenge-cookie expiry before weak-gate
  verification or plugin work. This is pinned by `web_runtime` coverage for expired
  out-of-band cookies and PgBouncer-backed Postgres runtime coverage for expired active
  method cookies.
- Challenge completion now validates encrypted-cookie structural requirements before
  weak-gate verification. Out-of-band completion rejects missing response MAC before
  weak-gate work, and active-method completion rejects missing method challenge state
  before weak-gate work.
- Out-of-band completion now derives the attempt id from the encrypted challenge cookie
  instead of accepting it from the response body. The cookie is the runtime-owned
  continuation handle for both the attempt and challenge.
- Postgres out-of-band challenge issue now gets generated response-secret material and
  method work together from the registered method plugin. The runtime uses that
  plugin-owned secret for challenge-cookie fast-fail construction and method commit work;
  applications no longer manufacture OTP/code secrets on the Postgres runtime path.
- `MethodChallengeCookieContract` now models challenge identity as part of the generic
  active-challenge cookie primitive for out-of-band, message-signature, origin-bound
  public-key, and federated-identity methods. Tests pin that encrypted challenge cookie
  contracts include both attempt id and challenge id in fields and associated context, so
  challenge identity cannot drift into method-specific optional state.
- Out-of-band challenge completion now carries the submitted code inside the
  secret-bearing `CompleteOutOfBandChallengeResponse` type. Generic and Postgres runtimes
  verify fast-fail from that typed response instead of accepting a separate
  response-secret argument, matching the configured-secret response boundary.
- Live code now names the configured shared-secret OTP proof family
  `ProofFamily::SharedSecretOtp`, while the first concrete plugin remains the TOTP method
  with method label `totp`. This keeps HOTP or other shared-secret OTP methods under the
  same lower-core family instead of creating plugin-shaped proof families.
- Active-proof continuation recovery result: the runtime now issues a MAC-backed
  continuation credential when starting an active-proof attempt, decodes it from the
  encrypted continuation cookie, and derives the attempt id from that credential for
  challenge issue, known-subject configured-secret completion, full-authentication
  completion, step-up completion, and trusted-device active revival. This was verified
  through the focused generic `web_runtime` filter and the PgBouncer-backed
  `postgres_runtime` filter. The remaining health check is to keep direct reducer tests
  clearly separated from runtime-facing APIs, because reducer/internal command material
  may still carry attempt ids after the runtime has derived them.
- Active-proof continuation recovery coverage result: dedicated PgBouncer-backed Postgres
  runtime coverage now includes step-up completion as well as existing-attempt challenge
  issue, known-subject configured-secret completion, full-authentication completion, and
  trusted-device active revival. The focused isolated filter passed with 34 auth runtime
  tests.
- Active-proof attempt start subject-binding recovery result: semantic runtime inputs no
  longer accept a caller-supplied `subject_id`. Step-up attempt starts derive subject from
  a validated session cookie and loaded session record. Trusted-device active-revival
  attempt starts derive subject/device from a validated trusted-device cookie and loaded
  credential record. Unauthenticated first-challenge ceremonies remain fused through
  method/plugin dispatch so subject binding happens only after method-owned verification
  or resolution. Generic and Postgres runtime tests now cover source-bound starts and
  missing-cookie no-write behavior.
- Credential lifecycle design gap: current satisfied proofs carry proof family/method and
  optional subject binding, but not the credential instance or recovery authority that
  produced the proof. That is not enough for factor-independence or factor-collapse
  analysis. Before building reset/recovery flows, the lower proof record shape likely
  needs credential-instance provenance.
- Do not confuse reducer/internal command material with runtime-facing input. It is fine
  for reducer commands and tests to carry an `ActiveProofAttemptId` after the runtime has
  derived it from a continuation cookie. It is unhealthy for public or adapter-facing
  semantic inputs to let applications choose or replay a naked attempt id.
- `auth_core` has a module-level `allow(dead_code, unused_imports)`. That is tolerable
  only while auth is a private WIP executable model. It must not survive into public auth,
  because it can hide stale surfaces, unused bypass paths, and design drift.
- Attempting to remove that allow while `auth_core` is still private produced hundreds of
  normal-check warnings because the public crate does not yet use the private auth model.
  Keep normal package checks clean for now, but treat removing the allow as part of the
  same work as exposing or wiring the real auth surface.
- Auth cookie suffix defaults are configurable, but the current defaults are too generic
  for Paranoid's prefix discipline. They should default to Paranoid-owned names so a
  future app that accepts defaults is unlikely to collide with app-owned cookies.
- Auth cookie suffix defaults now use Paranoid-owned names: `__paranoid_auth_session`,
  `__paranoid_auth_trusted_device`, and `__paranoid_auth_active_proof_challenge`.
- `auth_core` is crate-private today, and its module-root re-exports have been tightened
  to `pub(crate)` so auth cannot become a public pile of planner/runtime internals by
  accidentally changing one module modifier.
- Keep this ledger short and live. When an item is fixed and covered by tests, either move
  the durable decision into `AUTH_DESIGN.md` or remove the item with the relevant
  code/test reference.

## Fast-Fail Matrix Audit Findings

- Out-of-band challenge completion has the right pre-state rejection shape: the runtime
  verifies the encrypted challenge cookie and submitted response MAC before loading
  attempt, challenge, subject, or method state.
- Out-of-band resend has the right pre-state continuation shape: the runtime validates an
  unexpired out-of-band challenge cookie before loading the attempt/challenge or appending
  resend delivery work.
- Unauthenticated fused attempt-start plus challenge-issue paths have a runtime-owned weak
  gate before creating write-amplifying attempt/challenge state.
- Active-method challenge issue and completion have the right abstract runtime shape for
  message signatures, origin-bound public keys, and federated assertions: runtime-owned
  nonce/cookie construction, plugin-owned verification, and authoritative post-gate
  completion.
- Email OTP subject resolution now happens after stateless fast-fail inside the same
  Postgres runtime transaction that loads reducer state and commits the proof. Keep method
  subject resolution on the transaction-shaped post-gate boundary; do not move it back to
  a separate pool read.
- Direct known-subject TOTP currently fast-fails only through the weak gate. Wrong TOTP
  values still require loading the subject verifier. That is the conventional lane, not
  the stronger challenge-bound Bloom lane.
- Challenge-bound TOTP Bloom fast-fail is modeled as a primitive and method-adapter
  contract, but no runtime path or first-party plugin issues the Bloom challenge or
  verifies definite misses before DB.
- Recovery-code success is correctly one-time and atomic, and failure does not consume the
  code. The stronger pre-lookup fast-fail shape is not designed yet.
- Message-signature families are represented and tested with method-registry test plugins,
  including pre-state verification and optional authoritative confirmation. The
  first-party password-derived signature method that seals verifier material at challenge
  issue is not built.
- Origin-bound public-key and federated-identity families are represented and tested with
  method-registry test plugins. Mature-crate-backed WebAuthn/passkey, OIDC, and SAML
  implementations are not built.
- Weak-gate verification is runtime-owned and can mint pre-state evidence, but concrete
  Hashcash, human challenge, or risk gate implementations are not built.

## Method Families

- Decide whether auth v1 includes challenge-bound TOTP Bloom fast-fail or only direct
  known-subject TOTP.
- Define the first-party password-derived signature method:
    - salt/verifier construction;
    - sealed verifier payload;
    - canonical signed message format;
    - weak-gate binding to signature or signed payload;
    - authoritative verifier/version recheck after signature success.
- Decide whether deterministic email OTPs are a separate verification/reset helper or out
  of scope for auth v1.
- Define recovery-code public shape so impossible submissions can fail before expensive
  lookup work.
- Choose mature crates for TOTP, WebAuthn/passkeys, OIDC/JWT/JWKS, and SAML before
  implementing those protocol plugins.

## Credential Lifecycle And Recovery

- Define credential-instance identity and metadata:
    - credential family;
    - concrete method;
    - instance id;
    - subject id;
    - lifecycle state;
    - recovery/reset authorities;
    - whether proofs from this instance can be counted as independent from other
      credentials in a transition.
- Define the credential lifecycle policy layer alongside `ProofPolicy`. It must answer
  which proof stacks can add, replace, remove, reset, recover, or disable each credential
  type, and when proof independence is mandatory.
- Define factor-collapse checks. Password plus email OTP must not count as two independent
  factors for a transition if the password credential is resettable by that same email
  path. Apply the same analysis to TOTP resets, recovery-code regeneration, passkey
  removal, OIDC-linked recovery, and admin/support intervention.
- Define pending-action records for long waits:
    - scheduled subject/account deletion;
    - delayed second-factor reset;
    - delayed credential replacement;
    - cancellation conditions;
    - expiration;
    - durable notice requirements;
    - atomic execution preconditions.
- Define admin/support recovery as a Paranoid-shaped verified intervention, not an
  application side-door mutation. The core should not know app staff roles, but it should
  enforce audit, notices, waiting periods, target credential context, and post-action
  revocation once the app has supplied a verified admin/support authority.
- Decide how subject-wide revocation interacts with credential lifecycle mutations: which
  changes revoke all sessions/devices immediately, which wait until execution, and which
  merely require step-up freshness.
- Ensure lower-core records preserve room for credential instance ids in satisfied proofs
  and lifecycle mutations. Without instance identity, independence analysis and
  factor-collapse prevention will be too blunt.

## Lifecycle And Replay

- Finalize tripwire behavior:
    - normal previous-secret grace;
    - stale concurrent request races;
    - conclusive replay outside grace;
    - targeted revocation;
    - subject-wide revocation.
- Decide exactly which mismatch signals automatically revoke, and which only reject and
  audit.
- Verify trusted-device previous-secret grace cannot keep stolen credentials alive
  indefinitely.

## Storage And Runtime

- Finish the concrete Postgres auth schema and migration validation.
- Ensure every storage path is transaction-pooler safe and byte-stable.
- Pin operation counts for hot auth paths once schema and runtime are less fluid.
- Finish durable effect integration so external delivery is committed atomically with auth
  transitions.
- Define how method-owned state tables register schema, preconditions, mutations, and
  durable effects without bypassing core invariants.
- Design the public configuration and mounted runtime facade. It must be high-level enough
  that applications configure methods, storage, callbacks, route policy, cookie policy,
  CSRF policy, and lifecycle policy without manually sequencing proof ceremonies or
  security-sensitive response effects.

## Audit And Tests

- Build the realistic adversarial application-lifecycle suite described in
  `AUTH_DESIGN.md`. It should mount the intended public auth system and exercise a full
  subject lifetime, including normal flows, recovery, credential changes, deletion waits,
  durable effects, race attempts, replay attempts, enumeration attempts, and attack
  traffic.
- Build the audit-event coverage matrix.
- Add method-family tests for weak failure budgets:
    - no account lockout;
    - no consuming initiating strong proof on weak failure;
    - failed recovery-code submissions do not consume codes;
    - weak-gate failures do not create write amplification.
- Add cookie-budget and false-negative tests for challenge-bound TOTP Bloom filters.
