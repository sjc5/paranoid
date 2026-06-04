# Auth Roadmap

This is the dependency-ordered checklist from the current private auth-core state to
public alpha. It is not a taxonomy of work areas. Earlier phases contain decisions and
invariants that make later work easier, safer, and less likely to be rewritten.

A checked item means the deliverable exists in live design, code, tests, and durable notes
well enough that later work may rely on it.

This roadmap is grounded in the current auth notes, the raw-note design intent, and the
live `auth_core` module/test shape. The raw notes are not implementation instructions, but
they preserve important original intent: app-owned auth, database-authoritative success,
stateless rejection gates, no account lockouts, active attempts, continuation credentials,
trusted-device lifecycle, proof stacks, auditability, and config-driven mounted
ergonomics.

## Where We Are Now

Auth-core readiness estimate: about 42%.

Auth is private WIP behind the `__auth_wip` feature. The lower-core planner, runtime-owned
continuation/cookie shape, fast-fail challenge model, Postgres runtime slices, method
registry skeleton, and satisfied-proof provenance model are partially built and tested.

The largest unfinished areas are fast-fail implementation and test gap closure, credential
lifecycle and recovery policy, recovery-authority metadata, first-party production
methods, durable effect integration, public mounted APIs, client WASM/TypeScript, public
docs, and the adversarial lifecycle suite.

Standing design rules live in `AUTH_DESIGN.md`. Unresolved questions live in
`AUTH_OPEN_QUESTIONS.md`. This file is the ordered work plan.

## Phase 0: Close Model-Blocking Questions

This phase must stay first. These decisions define the shape of everything downstream.
Feature work that depends on one of these questions should wait until the relevant item is
closed.

- [x] Review every item in `AUTH_OPEN_QUESTIONS.md` and move resolved decisions into
      `AUTH_DESIGN.md` or this roadmap.
- [x] Reduce `AUTH_OPEN_QUESTIONS.md` to genuinely open questions, not historical ledger
      noise.
- [x] Complete the transition-by-transition fast-fail audit against the matrix in
      `AUTH_DESIGN.md`.
- [x] For every fast-fail matrix row, record the exact pre-state rejection gate and
      authoritative post-gate boundary.
- [x] Decide whether each fast-fail matrix row is already satisfied, needs code, needs
      tests, or needs redesign.
- [x] Decide the public-alpha first-party method set.
- [x] Decide whether challenge-bound TOTP Bloom fast-fail is public-alpha scope.
- [x] Decide the recovery-code fast-fail shape: opaque sealed base58 token carrying
      subject id plus random token, with parse/decrypt/tag and subject-mismatch rejection
      before DB.
- [ ] Decide the mature crate or audited wrapper choice for the alpha TOTP implementation.
- [x] Finalize the session/trusted-device lifecycle semantics that affect storage and
      cookies: refresh window, previous-secret grace, concurrent stale-cookie behavior,
      tripwire behavior, trusted-device revival, and trusted-device expiry.
- [x] Decide which credential mismatches automatically revoke and which only reject/audit.
- [x] Define credential-instance metadata.
- [x] Define recovery-authority metadata.
- [x] Define lifecycle policy checks that reject apparent factor independence when
      recovery/reset authorities overlap.
- [ ] Define weak-gate policy at the architecture level: native proof of work, human/risk
      adapters, proof binding, ceremony budgets, and delivery cooldowns.
- [ ] Decide whether the generic runtime is retained as production substrate or test/model
      scaffolding once the Postgres runtime is complete.
- [ ] Decide the public mounted API shape well enough that lower-layer APIs can be judged
      against it.

## Phase 1: Lock Lower-Core And Runtime Invariants

This phase makes the reducer/runtime/storage boundary trustworthy before real methods and
public APIs depend on it.

- [x] Model the reducer as an I/O-free planner over loaded state plus commands.
- [x] Model atomic commit work separately from response effects.
- [x] Require response effects to be released only after commit succeeds.
- [x] Model sessions as database-authoritative records with cookie-carried rejection
      ceilings.
- [x] Model trusted devices as database-authoritative rotating credentials.
- [x] Store MACs of session secrets, not plaintext bearer material.
- [x] Store MACs of trusted-device secrets, not plaintext bearer material.
- [x] Make fresh session ids runtime-owned.
- [x] Make fresh trusted-device credential ids runtime-owned.
- [x] Make fresh active-proof attempt ids runtime-owned.
- [x] Make fresh active-proof challenge ids runtime-owned.
- [x] Reject direct runtime calls that carry runtime-owned fresh lifecycle ids.
- [x] Make active-proof continuation use id plus secret, not a naked attempt id.
- [x] Derive active-proof attempt id from continuation cookies for runtime-facing paths.
- [x] Derive challenge id and attempt id from encrypted challenge cookies on completion.
- [x] Validate loaded-state contracts immediately after adapter load.
- [x] Separate reducer/internal command material from runtime-facing semantic inputs.
- [ ] Add tests proving stateless cookie or challenge material cannot grant positive auth
      without authoritative state, except the bounded safe-read path.
- [x] Pin the refresh-window write-rate invariant: active sessions refresh only in the
      configured refresh window, not on every request.
- [x] Add tests for concurrent-refresh grace from parallel tabs or requests.
- [x] Add tests for finalized tripwire and previous-secret grace behavior.
- [x] Verify trusted-device previous-secret grace cannot keep stolen credentials alive
      indefinitely.
- [ ] Audit the generic runtime path before any public auth exposure.
- [ ] Remove the private-WIP dead-code allowance before exposing any auth API.

## Phase 2: Pin Fast-Fail And Abuse-Resistance Guarantees

This phase turns the core thesis into executable guarantees before method implementation
spreads those assumptions across the system.

- [x] Model encrypted challenge cookies as pre-state rejection material.
- [x] Put out-of-band response MAC verification before state load.
- [x] Put out-of-band challenge cookie validation before resend state load.
- [x] Put challenge expiry and structural validation before weak-gate or plugin work.
- [x] Model runtime-owned weak-proof gate evidence.
- [x] Require write-amplifying unauthenticated challenge start to pass cheap preflight.
- [x] Model challenge-bound configured-secret Bloom filters.
- [x] Decide that account-level lockouts are not the primary defense because they create
      denial-of-service risk.
- [x] Model weak failure budgets on active-proof attempts.
- [ ] Add tests proving wrong out-of-band codes reject before any database work.
- [ ] Add tests proving resend rejects before database work unless the encrypted challenge
      cookie validates.
- [ ] Add tests proving active-method challenge completion verifies method-owned pre-state
      material before authoritative state load.
- [ ] Add method-by-method tests proving impossible submissions reject before DB where the
      design claims they should.
- [ ] Add operation-count tests for every fast-fail claim that depends on avoiding storage
      work.
- [ ] Implement native Hashcash-style proof-of-work weak gate.
- [ ] Bind proof-of-work evidence to the proof attempt so one solved gate cannot be reused
      across many password or TOTP guesses.
- [ ] Implement callback/adaptor shape for Turnstile, reCAPTCHA, self-hosted CAPTCHA, or
      other human challenges.
- [ ] Implement callback/adaptor shape for application risk engines.
- [ ] Define progressive friction rules.
- [ ] Define out-of-band delivery cooldown and dedupe policy.
- [ ] Add tests proving there are no account-level lockouts.
- [ ] Add tests proving identifier-level controls cannot let attackers deny legitimate
      users access.
- [ ] Add tests proving exhausted weak budgets invalidate only the ceremony, not the
      subject or identifier.
- [ ] Add tests proving weak-gate failures do not create write amplification.
- [ ] Add tests proving weak failures do not consume strong proof material.
- [ ] Add tests proving failed recovery-code submissions do not consume recovery codes.
- [ ] Add tests proving out-of-band delivery dedupe and cooldown bound harassment without
      revealing identifier existence.

## Phase 3: Finish Proof Policy And Provenance

This phase must precede credential lifecycle and recovery, because lifecycle policy cannot
reason about factor independence without stable proof sources.

- [x] Model core-owned proof families.
- [x] Model message signatures as one proof family covering password-derived, SSH, wallet,
      and similar signing methods.
- [x] Model online-guessing risk on method declarations.
- [x] Make method declaration constructors crate-owned while auth is WIP.
- [x] Model method adapter responsibilities by family.
- [x] Centralize proof-stack sufficiency in core, not plugins.
- [x] Require pre-state active-method verification before optional authoritative
      confirmation.
- [x] Persist satisfied-proof source provenance as kind plus stable byte id.
- [x] Record recovery-code source as the consumed recovery-code credential instance.
- [x] Record trusted-device proof evidence against the trusted-device credential id.
- [x] Record email OTP source as the verified identifier binding.
- [x] Record message-signature source as a credential instance.
- [x] Record origin-bound public-key source as a credential instance.
- [x] Record federated-identity source as an external authority.
- [x] Require multi-proof stack requirements to have known distinct sources by default.
- [x] Reject source-less multi-proof stacks when known distinct sources are required.
- [x] Reject same-source multi-proof stacks when known distinct sources are required.
- [x] Add policy tests for factor-collapse examples: password reset by email, TOTP reset
      by session, recovery-code regeneration, passkey removal, OIDC-linked recovery, and
      admin/support intervention.
- [ ] Decide how lower-risk transitions may intentionally allow non-independent proofs
      without making that easy to do accidentally.
- [ ] Design any future custom-method/plugin API as a reviewed registry boundary, not by
      exposing low-level method constructors.

## Phase 4: Define Credential Lifecycle And Recovery

This phase is where Paranoid stops being only a login/session engine and becomes a full
auth lifecycle system. It must happen before public APIs, because public APIs need to
expose safe lifecycle transitions rather than low-level mutation helpers.

- [ ] Finish production credential records for families, methods, instances, lifecycle
      states, and source ids.
- [x] Define recovery-authority graph semantics.
- [x] Persist core credential-instance metadata, recovery-authority edges, and lifecycle
      authority-source bindings in the Postgres auth schema.
- [x] Load persisted lifecycle metadata into a transaction-shaped lifecycle action
      decision that distinguishes immediate authorization, delayed-action requirement, and
      rejection.
- [x] Define the first concrete credential reset planning transition over that decision:
      immediate authorization with audit/notice/optional subject revocation, or delayed
      pending-action creation with audit/notice.
- [x] Add Postgres runtime facades for authenticated and unauthenticated credential-reset
      planning that construct lifecycle authority internally, generate pending-action ids
      internally, and consume recovery active-proof attempts atomically with the reset
      plan.
- [x] Define the first concrete credential reset execution transition: immediate
      lifecycle-authorized reset or matured pending reset, with method-owned verifier
      work, pending-action closure, audit, execution notice, and optional subject
      auth-state revocation.
- [x] Add Postgres runtime facades for credential-reset execution that construct lifecycle
      authority and method-owned reset work internally instead of accepting
      caller-provided `method_commit_work` or lifecycle authority facts.
- [x] Reject direct credential-reset planning and execution commands through the generic
      Postgres web runtime path.
- [ ] Define add-credential transitions.
- [ ] Define replace-credential transitions.
- [ ] Define remove-credential transitions.
- [ ] Define credential rotation transitions.
- [ ] Define authenticated credential reset transitions.
- [ ] Define unauthenticated recovery transitions.
- [x] Define password reset non-degradation policy so reset cannot instantly weaken a
      subject that already has independent credentials.
- [ ] Define second-factor reset policy.
- [ ] Define email or out-of-band identifier change policy.
- [ ] Define recovery-code generation and regeneration policy.
- [ ] Define passkey removal/replacement policy.
- [ ] Define OIDC-linked recovery policy.
- [ ] Define last-strong-factor protection in core lifecycle policy.
- [x] Define lower-core account or subject-auth-state deletion scheduling.
- [x] Define lower-core subject-auth-state deletion cancellation.
- [x] Define credential-reset pending action records.
- [x] Define long-wait pending action records for subject-auth-state deletion.
- [ ] Define long-wait pending action records for second-factor reset and delayed
      credential replacement scheduling.
- [x] Define credential-reset pending-action execution preconditions.
- [x] Define credential-reset pending-action cancellation preconditions and authenticated
      runtime facade.
- [x] Define credential-reset pending-action expiry semantics and quiet cleanup boundary.
- [x] Define shared pending-action semantics for credential-targeted reset, replacement,
      removal, regeneration, and subject-targeted deletion.
- [x] Define lower-core pending-action execution and cancellation for delayed
      credential-targeted replacement, removal, and regeneration.
- [x] Add reducer tests proving delayed replacement supersedes the target credential,
      delayed removal revokes the target credential, and delayed regeneration preserves
      target state while applying method-owned work.
- [x] Add Postgres runtime facades for delayed non-reset credential-targeted action
      execution and authenticated cancellation, with method work constructed internally by
      the registered target-credential plugin.
- [x] Define pending-action execution preconditions for subject-auth-state deletion.
- [x] Add Postgres runtime facades for delayed subject-auth-state deletion execution and
      authenticated cancellation, loading subject pending-action records internally and
      deriving cancellation authority from the current live session.
- [ ] Define pending-action execution preconditions for other subject-targeted waits.
- [ ] Define how second-factor reset is selected as a policy role over credential reset,
      without making it a separate credential kind.
- [ ] Define admin/support recovery as a Paranoid-shaped verified intervention.
- [x] Define durable notices for credential reset authorization, delayed reset scheduling,
      and reset execution.
- [x] Define lower-core durable notices for non-reset pending replacement, removal, and
      regeneration execution/cancellation.
- [x] Define lower-core durable notices for subject-auth-state deletion scheduling,
      execution, and cancellation.
- [ ] Define durable notices for credential additions, mounted removals, admin
      interventions, and mounted deletion integration.
- [ ] Define which lifecycle mutations require immediate subject-wide revocation.
- [ ] Define which lifecycle mutations require step-up freshness.
- [ ] Define which lifecycle mutations require delayed execution.
- [ ] Add tests proving applications cannot mutate credential lifecycle state by calling
      lower-level storage helpers directly through the mounted API.

## Phase 5: Build Production First-Party Methods

This phase should start only after the method contract, fast-fail boundaries, and
credential lifecycle metadata are stable enough that real methods do not encode the wrong
assumptions.

- [x] Build an email OTP skeleton with runtime-owned response-secret generation.
- [x] Resolve email OTP subject/source inside the post-gate transaction.
- [x] Build direct known-subject TOTP skeleton.
- [x] Build recovery-code skeleton with atomic consume-on-success.
- [x] Build test-plugin lanes for message signature, origin-bound public key, and
      federated identity.
- [x] Implement sealed opaque recovery-code token sealing and parsing inside the
      recovery-code method.
- [x] Add tests proving malformed or guessed sealed recovery codes reject before DB.
- [x] Add tests proving sealed recovery codes for the wrong known subject reject before
      DB.
- [ ] Implement the lifecycle/runtime path that generates and stores new user-visible
      recovery codes.
- [x] Give TOTP a stable configured-secret credential instance id.
- [ ] Implement real TOTP using the selected mature crate or audited RFC-6238 wrapper.
- [ ] Implement challenge-bound TOTP Bloom fast-fail as a real first-party method lane.
- [ ] Add cookie-budget tests for challenge-bound TOTP Bloom filters.
- [ ] Add false-negative safety tests for challenge-bound TOTP Bloom filters.
- [ ] Implement password-derived message-signature auth.
- [ ] Define password salt/verifier construction.
- [ ] Define canonical signed message format for password-derived signatures.
- [ ] Seal verifier material into the message-signature challenge when safe.
- [ ] Recheck authoritative verifier/version after message-signature pre-state success.
- [ ] Bind password-derived proof-of-work to the signature or signed payload.
- [ ] Keep WebAuthn/passkey contract hooks modeled for post-alpha implementation.
- [ ] Keep OIDC contract hooks modeled for post-alpha implementation.
- [ ] Keep SAML contract hooks modeled for post-alpha implementation.
- [ ] Decide whether deterministic email OTPs are a separate helper or out of scope.
- [ ] Keep SMS/postal out-of-band method scope post-alpha unless a later product decision
      moves one forward.

## Phase 6: Finish Storage, Schema, And Durable Effects

This phase turns the executable model into a production Postgres subsystem.

- [x] Build Postgres runtime slices for core session, trusted-device, active-proof, and
      selected method paths.
- [x] Route Postgres auth paths through transaction-pooler-safe query helpers.
- [x] Store internal identifiers and secrets with byte-stable database semantics.
- [x] Commit method-owned state atomically through registered method work.
- [x] Add auth-specific source guards for production auth Postgres code covering portable
      query constructors, raw pool bypasses, session-level Postgres features,
      transaction-local `set_config`, database-owned time, and schema-version ordering.
- [ ] Finish concrete Postgres auth schema.
- [ ] Finish auth migration execution and validation.
- [x] Make the core auth Postgres store derive from Paranoid's DB foundation by default:
      DB bootstrap schema, shared schema ledger, and schema-local core table names.
- [x] Make first-party Postgres method configs derive schema-local method table names from
      the DB foundation schema by default.
- [x] Build the private WIP auth bootstrap facade that runs after DB foundation bootstrap,
      constructs the core store plus registered method plugins from one DB bootstrap
      config, and performs auth migration or validation without application-managed table
      choreography.
- [x] Add end-to-end auth bootstrap tests proving the facade uses the shared DB foundation
      schema ledger, schema-local core/method tables, transaction-pooler-safe SQL, and no
      auth advisory-lock path.
- [ ] Pin operation counts for hot auth paths once schema is less fluid.
- [ ] Integrate durable effects with Paranoid queue.
- [ ] Commit delivery commands atomically with auth transitions.
- [ ] Add stale delivery and retry semantics for out-of-band messages and notices.
- [ ] Add registration coverage for every method-owned table schema, validation,
      preconditions, mutations, and durable effects without bypassing core invariants.
- [ ] Remove any auth DB tests that skip when a database resource is missing; missing
      required resources must fail loudly in the final gate.
- [ ] Add PgBouncer transaction-mode coverage for every production auth storage path.
- [ ] Add schema-validation tests for byte-stable and collation-safe auth tables.

## Phase 7: Build Web Transport And Mounted Runtime

This phase is the public product surface. It should consume the lower layers, not expose
them.

- [x] Model response materialization for cookies.
- [x] Model web transport boundary for cookies and CSRF cycling.
- [ ] Define public mounted-API input limits for every auth request type.
- [ ] Add mounted-runtime tests proving malformed public inputs reject before storage work
      where possible.
- [ ] Add tests proving oversized public inputs fail loudly without truncation, fallback,
      or implementation-shaped tolerances.
- [ ] Add cookie-size budget tests for every auth cookie family.
- [ ] Design the public mounted auth facade.
- [ ] Design the public auth configuration object.
- [ ] Design route registration or handler construction.
- [ ] Design middleware construction.
- [ ] Design route-level auth requirements.
- [ ] Design application subject mapping hooks.
- [ ] Design durable integration callbacks without letting apps sequence auth ceremonies.
- [ ] Expose mounted APIs that prevent apps from setting or assembling auth cookies
      manually.
- [ ] Expose mounted APIs that prevent apps from deciding proof sufficiency manually.
- [ ] Expose mounted APIs that prevent apps from enqueueing required auth notices
      manually.
- [ ] Wire automatic CSRF behavior for auth routes that need it.
- [ ] Cycle CSRF tokens on session creation, logout, step-up, and other session-security
      mutations.
- [ ] Add end-to-end mounted-runtime tests proving response cookies are rendered only
      after successful storage commit.

## Phase 8: Build Client WASM And TypeScript

This phase is required for the browser-side parts of password-derived signing, proof of
work, and app encryption subkeys.

- [ ] Define the client package boundary and build pipeline.
- [ ] Implement password-derived key generation/signing support in WASM.
- [ ] Implement message canonicalization helpers for message-signature auth.
- [ ] Implement proof-of-work generation support.
- [ ] Implement minimum password length and password policy helpers.
- [ ] Implement sub-key derivation for app encryption keys and E2EE use cases.
- [ ] Test password-derived auth deriving signing material and additional app subkeys
      without cross-context key reuse.
- [ ] Define browser storage guidance for any client-side non-secret state.
- [ ] Define TypeScript types for public auth requests/responses.
- [ ] Add browser-oriented tests for password-derived auth and proof-of-work helpers.
- [ ] Add WASM packaging tests.

## Phase 9: Build Audit, Privacy, And Identity Coverage

This phase can start earlier where it helps, but it cannot close until the production
runtime and credential lifecycle surfaces exist.

- [ ] Build the immutable audit-event coverage matrix for every security-significant auth
      transition.
- [ ] Add tests proving safe-read cache hits are not recorded as lifecycle audit events.
- [ ] Add tests proving public identifier flows do not reveal whether an email, account,
      method, or identifier exists.
- [ ] Add tests proving user-facing responses stay indistinguishable across registered and
      unregistered identifiers where policy requires it.
- [ ] Define the public `SubjectId` boundary so auth does not model organizations, billing
      accounts, resource ownership, route authorization, or app-specific identity shapes.
- [ ] Define display metadata boundaries for user-agent strings.
- [ ] Define IP-address boundaries so IPs remain infrastructure guardrails, not auth-core
      identity signals.
- [ ] Add tests proving IP addresses are not required as auth-core identity inputs.

## Phase 10: Write Public API And Docs

This phase should be late. Public docs should describe the actual mounted system, not an
intermediate planning model.

- [ ] Decide public module names for auth.
- [ ] Expose high-level mounted auth APIs instead of lower-core planner internals.
- [ ] Write public auth README material.
- [ ] Write public method configuration docs.
- [ ] Write public lifecycle/recovery policy docs.
- [ ] Write public threat-model docs that are honest about what Paranoid does and does not
      protect against.
- [ ] Write public deployment docs for Postgres, cookies, CSRF, durable effects, and
      external delivery providers.
- [ ] Write migration docs for auth schema.
- [ ] Ensure the public alpha API supports the intended one-config mounted-system shape.

## Phase 11: Build The Adversarial Test Program

This phase is the release-confidence program. It should test the mounted system through a
realistic fictitious application rather than only reducer internals.

- [ ] Build the realistic full-subject lifecycle suite.
- [ ] Cover registration and first login.
- [ ] Cover login through each public-alpha method.
- [ ] Cover trusted-device creation, silent revival, active revival, and revocation.
- [ ] Cover step-up and freshness expiry.
- [ ] Cover adding, replacing, removing, and resetting credentials.
- [ ] Cover recovery-code use and regeneration.
- [ ] Cover account deletion scheduling, cancellation, and execution.
- [ ] Cover admin/support recovery intervention.
- [ ] Cover durable effect delivery, retry, and idempotency.
- [ ] Cover replay attacks against cookies, continuation credentials, and challenges.
- [ ] Cover stale commit races.
- [ ] Cover subject-wide revocation races.
- [ ] Cover enumeration attempts.
- [ ] Cover out-of-band harassment attempts.
- [ ] Cover weak-gate bypass attempts.
- [ ] Cover operation-count and no-waste assertions for hot paths.
- [ ] Cover PgBouncer transaction-pooler mode.
- [ ] Cover migration validation against adopted existing tables.
- [ ] Cover client WASM/TypeScript happy paths and adversarial paths.

## Phase 12: Release Gate

- [ ] Run full Rust gate.
- [ ] Run full Postgres isolated gate.
- [ ] Run full fuzz gate.
- [ ] Run full client WASM/TypeScript gate.
- [ ] Run full adversarial auth lifecycle suite.
- [ ] Run docs examples.
- [ ] Verify no auth WIP internals are public.
- [ ] Verify no stale maintainer notes contradict the released design.
- [ ] Verify public API names match the high-level Paranoid philosophy.
- [ ] Verify public alpha docs clearly mark remaining non-alpha features.
- [ ] release auth in public alpha
