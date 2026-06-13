# Auth Roadmap

This is the dependency-ordered checklist from the current private auth-core state to
public alpha. It is not a taxonomy of work areas. Earlier phases contain decisions and
invariants that make later work easier, safer, and less likely to be rewritten.

A checked item means the named deliverable has been addressed at the level described by
the item itself. Some checked items are design decisions, some are model/code slices, and
some are executable test guarantees. Do not read a design-decision checkbox as proof that
the corresponding runtime path is fully implemented or operation-count pinned.

Roadmap items should stay readable as deliverables plus exit criteria. Do not grow this
file into an implementation history. Detailed semantics belong in `AUTH_DESIGN.md`;
live-code audit findings belong in `AUTH_IMPLEMENTATION_LEDGER.md`; unresolved decisions
belong in `AUTH_OPEN_QUESTIONS.md`.

This roadmap is grounded in the current auth notes, the raw-note design intent, and the
live `auth_core` module/test shape. The raw notes are not implementation instructions, but
they preserve important original intent: app-owned auth, database-authoritative success,
stateless rejection gates, no account lockouts, active attempts, continuation credentials,
trusted-device lifecycle, proof stacks, auditability, and config-driven mounted
ergonomics.

## Where We Are Now

Auth backend-Rust readiness estimate: about 70%.

This estimate is for the backend Rust auth system only. It excludes the future client-side
WASM/TypeScript package and excludes final public documentation polish. It does include
the mounted backend API shape, Postgres runtime, first-party backend method plugins,
durable-effect Queue integration, schema/migration validation, public API exposure
choices, and backend test confidence.

Auth is still private WIP behind the `__auth_wip` feature, but it is no longer an early
prototype. The lower-core planner, runtime-owned continuation/cookie shape,
database-authoritative session/trusted-device lifecycle, fast-fail method paths, proof
provenance, credential lifecycle and recovery policy, recovery-authority metadata,
first-party email OTP/TOTP/recovery-code/password-signature backend methods, Postgres
runtime, mounted route service, durable-effect Queue bridge, and auth bootstrap are all
substantially implemented and tested.

The remaining backend Rust work is concentrated in these buckets:

- preserve the executable fast-fail and operation-count audit as public mounted APIs are
  finalized, so every claimed no-storage or bounded-storage path remains pinned by tests;
- finish the public mounted backend facade/configuration shape instead of leaving it as
  private mounted-system machinery behind `__auth_wip`;
- finish public backend route/response rendering and API exposure so applications mount
  one coherent auth system rather than lower inspection helpers;
- finish privacy/enumeration and adversarial lifecycle coverage through the mounted
  backend surface;
- remove broad private-WIP allowances and any remaining dead or stale auth surfaces before
  public exposure;
- run the full backend gate, including PgBouncer transaction-mode coverage.

Standing design rules live in `AUTH_DESIGN.md`. Unresolved questions live in
`AUTH_OPEN_QUESTIONS.md`. This file is the ordered work plan.

## Phase 0: Close Model-Blocking Questions And Design Choices

This phase must stay first. These decisions define the shape of everything downstream.
Feature work that depends on one of these questions should wait until the relevant item is
closed.

- [x] Review every item in `AUTH_OPEN_QUESTIONS.md` and move resolved decisions into
      `AUTH_DESIGN.md` or this roadmap.
- [x] Reduce `AUTH_OPEN_QUESTIONS.md` to genuinely open questions, not historical ledger
      noise.
- [x] Draft the transition-by-transition fast-fail matrix in `AUTH_DESIGN.md`.
- [x] For every fast-fail matrix row, record the intended pre-state rejection gate and
      authoritative post-gate boundary.
- [x] Record the current live-shape status for each fast-fail matrix row.
- [x] Decide the public-alpha first-party method set.
- [x] Decide whether challenge-bound TOTP Bloom fast-fail is public-alpha scope.
- [x] Decide the recovery-code fast-fail shape: opaque sealed base58 token carrying
      subject id plus random token, with parse/decrypt/tag and subject-mismatch rejection
      before DB.
- [x] Decide the mature crate or audited wrapper choice for the alpha TOTP implementation.
- [x] Finalize the session/trusted-device lifecycle semantics that affect storage and
      cookies: refresh window, previous-secret grace, concurrent stale-cookie behavior,
      tripwire behavior, trusted-device revival, and trusted-device expiry.
- [x] Decide which credential mismatches automatically revoke and which only reject/audit.
- [x] Define credential-instance metadata.
- [x] Define recovery-authority metadata.
- [x] Define lifecycle policy checks that reject apparent factor independence when
      recovery/reset authorities overlap.
- [x] Define weak-gate policy at the architecture level: native proof of work, human/risk
      adapters, proof binding, ceremony budgets, and delivery cooldowns.
- [x] Decide whether the generic runtime is retained as production substrate or test/model
      scaffolding once the Postgres runtime is complete.
- [x] Decide the public mounted API shape well enough that lower-layer APIs can be judged
      against it.

Phase 0 closure means the model-blocking decisions are recorded. It does not mean every
fast-fail claim is executable or operation-count pinned. The executable fast-fail audit is
tracked in Phase 2.

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
- [x] Add tests proving stateless cookie or challenge material cannot grant positive auth
      without authoritative state, except the bounded safe-read path.
- [x] Pin the refresh-window write-rate invariant: active sessions refresh only in the
      configured refresh window, not on every request.
- [x] Add tests for concurrent-refresh grace from parallel tabs or requests.
- [x] Add tests for finalized tripwire and previous-secret grace behavior.
- [x] Verify trusted-device previous-secret grace cannot keep stolen credentials alive
      indefinitely.
- [x] Audit the generic runtime path before any public auth exposure.

## Phase 2: Pin Fast-Fail And Abuse-Resistance Guarantees

This phase turns the core thesis into executable guarantees before method implementation
spreads those assumptions across the system.

Phase 2 exits when every live fast-fail row in `AUTH_DESIGN.md` has an executable
classification and every no-storage or bounded-storage claim is backed by a focused test.
Modeled-only or not-built rows must be named that way instead of treated as pinned.

- [x] Complete the executable transition-by-transition fast-fail audit against live code.
- [x] For every fast-fail matrix row, classify the runtime path as not built, modeled
      only, pinned private WIP route/runtime path, or fully pinned by tests.
- [x] Update the matrix whenever a row graduates from modeled intent to executable
      guarantee.
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
- [x] Add tests proving wrong out-of-band codes reject before any database work.
- [x] Add tests proving resend rejects before database work unless the encrypted challenge
      cookie validates.
- [x] Add tests proving active-method challenge completion verifies method-owned pre-state
      material before authoritative state load.
- [x] Add tests proving invalid direct TOTP weak gates reject before database work.
- [x] Add tests proving direct TOTP wrong-code handling with a valid weak gate reaches
      authoritative verifier state and spends only the active ceremony budget.
- [x] Add tests proving recovery-code malformed, guessed, and wrong-subject sealed tokens
      reject before database work.
- [x] Add tests proving plausible but unused sealed recovery-code tokens reject
      authoritatively without consuming stored recovery codes.
- [x] Audit current message-signature fast-fail coverage and record that it is
      method-registry/test-plugin coverage, not first-party password-derived auth.
- [x] Audit challenge-bound TOTP Bloom coverage and record the current runtime status in
      the fast-fail matrix.
- [x] Add method-by-method tests proving impossible submissions reject before DB where the
      design claims they should for the current first-party method set. Plausible sealed
      recovery-code tokens intentionally continue to authoritative lookup and are tested
      for non-consumption instead of no-storage rejection.
- [x] Add operation-count tests for every fast-fail claim that depends on avoiding storage
      work. Exit criteria: every built path that claims an empty database-operation
      observer has a focused assertion, every bounded-storage path has an exact operation
      sequence assertion, and the fast-fail matrix names any remaining modeled-only rows.
- [x] Add first-party password-derived message-signature tests proving wrong signatures
      reject before DB and successful signatures still recheck authoritative
      verifier/version state.
- [x] Add password-derived weak-gate binding tests proving a gate solved for one submitted
      signature rejects before DB when replayed with another submitted signature.
- [x] Add first-party challenge-bound TOTP Bloom tests proving definite misses reject
      before DB and possible hits perform authoritative verifier/replay checks.
- [x] Implement native Hashcash-style proof-of-work weak gate.
- [x] Bind proof-of-work evidence to the exact protected ceremony material so one solved
      gate cannot be reused across many password or TOTP guesses.
- [x] Implement callback/adaptor shape for Turnstile, reCAPTCHA, self-hosted CAPTCHA, or
      other human challenges.
- [x] Implement callback/adaptor shape for application risk engines.
- [x] Define progressive friction rules.
- [x] Define out-of-band delivery cooldown and dedupe policy.
- [x] Add tests proving there are no account-level lockouts in the built weak-failure
      paths.
- [x] Add tests proving the built identifier-level delivery control cannot let attackers
      deny legitimate users access.
- [x] Add tests proving exhausted weak budgets invalidate only the ceremony, not the
      subject or identifier.
- [x] Add tests proving weak-gate failures do not create write amplification.
- [x] Add tests proving weak failures do not consume strong proof material.
- [x] Add tests proving failed recovery-code submissions do not consume recovery codes.
- [x] Add tests proving the full out-of-band delivery dedupe and cooldown policy bounds
      harassment without revealing identifier existence.

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
- [x] Decide how lower-risk transitions may intentionally allow non-independent proofs
      without making that easy to do accidentally.
- [x] Design any future custom-method/plugin API as a reviewed registry boundary, not by
      exposing low-level method constructors.

## Phase 4: Define Credential Lifecycle And Recovery

This phase is where Paranoid stops being only a login/session engine and becomes a full
auth lifecycle system. It must happen before public APIs, because public APIs need to
expose safe lifecycle transitions rather than low-level mutation helpers.

Public mounted lifecycle route items in this phase share these exit criteria unless an
item says otherwise:

- route construction flows from the final one-config mounted auth system;
- route selection, CSRF checks, body limits, and body parsing happen before storage work;
- requests cannot supply lifecycle authority, method work, pending-action records,
  revocation choices, generated secrets, or internal subject/credential/source ids;
- responses expose only public committed outcomes, committed cookies, and appropriate
  user-visible material such as generated recovery codes after commit;
- PgBouncer-backed coverage proves successful execution plus the relevant no-storage,
  stale-state, wrong-subject, and operation-count boundaries.

- [x] Finish production credential records for families, methods, instances, lifecycle
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
- [x] Add Postgres runtime facades for authenticated credential-reset planning and delayed
      unauthenticated credential-reset scheduling that construct lifecycle authority
      internally, generate pending-action ids internally, and consume recovery
      active-proof attempts atomically only with delayed reset scheduling.
- [x] Define the first concrete credential reset execution transition: immediate
      lifecycle-authorized reset or matured pending reset, with method-owned verifier
      work, pending-action closure, audit, execution notice, and optional subject
      auth-state revocation.
- [x] Add Postgres runtime facades for credential-reset execution that construct lifecycle
      authority and method-owned reset work internally instead of accepting
      caller-provided `method_commit_work` or lifecycle authority facts.
- [x] Reject direct credential-reset planning and execution commands through the generic
      Postgres web runtime path.
- [x] Define add-credential transitions.
- [x] Add private Postgres runtime facade for authenticated credential addition, with
      runtime-generated credential id, session-derived lifecycle evidence, registered
      method-owned creation work, audit, notice, subject auth-state revocation, and a
      commit-time posture guard that rejects adding an ordinary or second-factor
      credential when the new credential would create a same-authority collapsed
      ordinary-plus-second-factor path.
- [x] Implement private, public-shaped mounted add-credential service over the private
      runtime facade, accepting only a configured addition method plus bounded
      method-specific creation payload and not exposing lifecycle context, authority
      graph, credential ids, or method work.
- [ ] Implement concrete public mounted add-credential route/user rendering over the
      mounted service.
- [x] Define replace-credential transitions.
- [x] Add private Postgres runtime facades and public-shaped mounted service outcomes for
      authenticated credential replacement planning and immediate execution, deriving
      lifecycle context from the live session, generating delayed pending-action ids
      internally, dispatching method-owned replacement work through the registered target
      method, rejecting stale step-up before target/method work, and rejecting direct
      caller-provided lifecycle context or method work.
- [ ] Implement concrete public mounted credential-replacement route/user rendering over
      the mounted service.
- [x] Define remove-credential transitions.
- [x] Add private Postgres runtime facades and public-shaped mounted service outcomes for
      authenticated credential removal planning and immediate execution, deriving
      lifecycle context from the live session, generating delayed pending-action ids
      internally, forbidding caller-provided method work, rejecting stale step-up before
      target work, and rejecting direct caller-provided lifecycle context.
- [x] Add a baseline commit-time last-active-credential guard for immediate and matured
      delayed removal execution.
- [ ] Implement concrete public mounted remove-credential route/user rendering over the
      mounted service.
- [x] Define credential rotation transitions.
- [ ] Implement concrete public mounted credential-rotation route/user rendering over the
      mounted service.
- [x] Define authenticated credential reset transitions.
- [x] Add private public-shaped mounted service outcomes for authenticated credential
      reset planning and immediate execution, accepting only the mounted credential handle
      returned by inventory, time, and reset method payload while preserving delayed reset
      execution for the delayed-action service.
- [ ] Implement concrete public mounted authenticated credential-reset route/user
      rendering over the mounted service.
- [x] Define unauthenticated recovery transitions.
- [x] Add private public-shaped mounted service outcomes for delayed unauthenticated
      recovery reset scheduling, deriving lifecycle authority from a validated
      `RecoverOrReplaceCredential` active-proof continuation inside the runtime. The safer
      mounted recovery target path accepts a configured target method and time, then
      resolves the active target credential for the recovered subject inside the runtime
      transaction.
- [x] Add private public-shaped mounted service outcomes for unauthenticated immediate
      recovery reset execution, deriving lifecycle authority and method work inside the
      runtime. The safer mounted recovery target path accepts a configured target method,
      time, and reset method payload, then resolves the active target credential for the
      recovered subject inside the runtime transaction.
- [x] Add reducer and Postgres runtime tests proving delayed unauthenticated recovery
      reset scheduling rejects wrong-use continuations, rejects subject-mismatched
      recovery attempts, consumes valid recovery attempts atomically with the delayed
      reset schedule, rejects immediate-policy scheduling without consuming the recovery
      attempt, rejects replay of the consumed proof-bound recovery continuation without
      creating another pending action, and does not accept caller-provided lifecycle
      authority or method work.
- [x] Add reducer and Postgres runtime tests proving unauthenticated immediate recovery
      reset execution rejects wrong-use continuations before DB, rejects delayed-only
      policy without scheduling or consuming the recovery attempt, builds method work
      internally, commits revocation/notices atomically, and consumes the recovery attempt
      in the reset commit. Mounted route-service coverage proves replay of the consumed
      proof-bound recovery continuation cannot execute the reset twice, commit duplicate
      method work, schedule duplicate notices, advance revocation, or recreate the
      consumed attempt. The configured-target path also rejects ambiguous active target
      credentials before method-owned reset work, notices, revocation, or recovery-attempt
      consumption. Mounted route-service coverage now pins the same ambiguous configured
      target failure through the no-session recovery ceremony, so route-shaped code cannot
      turn accepted recovery proof authority into caller-selected target reset work.
- [x] Add Postgres runtime coverage proving no-session recovery proof completion rejects a
      subject-bound continuation cookie before DB. The proof-completion step must bind the
      unbound recovery ceremony to the recovered subject and reissue an accepted
      proof-bound continuation cookie for the reset lanes; callers cannot smuggle an
      already subject-bound continuation into the proof-completion lane or use the initial
      unbound continuation to schedule or execute recovery reset work.
- [x] Add Postgres runtime operation-count coverage proving unauthenticated recovery reset
      scheduling and immediate execution reject runtime-bound subject continuations before
      DB. A subject-bearing active-proof continuation created from a live session is not
      recovery authority unless proof completion reissues it as proof-bound.
- [x] Add private Postgres runtime and mounted-service recovery-code ceremony that starts
      an unbound `RecoverOrReplaceCredential` attempt behind runtime-owned preflight,
      completes a sealed recovery-code proof through the method registry, binds the
      subject only after authoritative one-time code consume, and then feeds the delayed
      scheduling or immediate reset lanes.
- [x] Consolidate the private mounted no-session recovery boundary around one configured
      recovery flow: configured recovery proof method plus configured reset target method.
      The mounted no-session path no longer accepts a request-supplied target credential
      id for delayed scheduling or immediate reset execution.
- [x] Remove the lower Postgres no-session recovery reset helpers that accepted a target
      credential id. The unauthenticated recovery reset runtime lane now resolves the
      configured target method for the recovered subject inside the transaction.
- [x] Define password reset non-degradation policy so reset cannot instantly weaken a
      subject that already has independent credentials.
- [x] Define second-factor reset policy.
- [x] Define email or out-of-band identifier change policy.
- [x] Add lower-core subject lifecycle authority and pending-action vocabulary for
      out-of-band identifier change, including tests proving the candidate new identifier
      proof cannot authorize its own binding.
- [x] Implement Paranoid-owned out-of-band identifier binding records in the core Postgres
      schema/store, including lifecycle states, subject ownership, schema validation, and
      commit-time stale-state guards.
- [x] Implement lower-core immediate out-of-band identifier change execution: supersede
      current binding, activate candidate binding, add candidate lifecycle-authority
      source rows, revoke subject auth state, audit, and schedule notice atomically.
- [x] Implement method-owned out-of-band identifier binding work for first-party methods,
      so candidate binding reservation/proof state is created and consumed by the method
      registry rather than test-only seeding. The email OTP path now resolves the
      candidate out-of-band identifier source from method-owned challenge state, consumes
      the challenge, and creates a pending identifier binding through a runtime-owned
      candidate-binding reservation command.
- [x] Add private Postgres runtime facades for authenticated immediate and delayed
      out-of-band identifier change, deriving subject/current binding/candidate binding
      context internally instead of accepting lower-core command material.
- [x] Add reducer and Postgres runtime tests proving authenticated out-of-band identifier
      change planning creates pending subject-lifecycle target state internally,
      authenticated immediate execution activates only a stored pending candidate binding,
      and stale step-up is rejected before identifier-binding load.
- [x] Implement pending subject-lifecycle execution/cancellation facades for delayed
      out-of-band identifier change once method-owned binding work and runtime facades
      exist.
- [x] Add private mounted identifier-change service boundary over the Postgres runtime
      facades for authenticated planning, authenticated immediate execution, matured
      delayed execution, and authenticated cancellation. The mounted boundary accepts only
      source handles or pending-action handles plus time, and Postgres tests now route the
      concrete identifier-change paths through that service while still asserting notices
      and subject auth-state revocation.
- [ ] Implement concrete public mounted identifier-change routes/user rendering once the
      full mounted auth runtime exists, including old/new reachable-channel rendering for
      committed notices.
- [x] Define recovery-code generation and regeneration policy.
- [x] Add lower-core, Postgres runtime, and private mounted-service planning for
      authenticated credential-set regeneration. Planning derives lifecycle authority from
      the live session, rejects stale step-up before target lifecycle load, records
      immediate authorization or internally creates a delayed pending action, emits audit
      and notice work, and does not accept caller-provided lifecycle authority,
      pending-action records, method work, or generated recovery codes.
- [x] Add lower-core, Postgres runtime, and private mounted-service execution for
      authenticated immediate credential-set regeneration. Execution derives lifecycle
      authority from the live session, rejects stale step-up before target lifecycle load
      or method work, obtains regeneration work only through the registered target method,
      commits audit, notice, method work, and subject-auth-state revocation atomically,
      and projects generated recovery codes only after commit.
- [ ] Implement concrete public mounted credential-regeneration route/user rendering over
      the mounted service, including post-commit generated-code projection.
- [x] Define passkey removal/replacement policy.
- [x] Define OIDC-linked recovery policy.
- [x] Define last-strong-factor protection in core lifecycle policy beyond the baseline
      "subject must have another active credential" removal guard.
- [x] Replace the row-count-only credential-removal guard with a commit-time
      required-posture precondition: ordinary credential removal must leave another
      access-preserving active credential, and second-factor removal must leave another
      active credential carrying the second-factor policy role.
- [x] Extend after-state last-strong-factor evaluation across the built subject credential
      and recovery-authority graph where current lifecycle mutations can change
      core-visible credential posture.
- [ ] Apply the same after-state posture rule to future executable method-specific
      lifecycle surfaces that can remove, replace, unlink, or downgrade a core-visible
      credential or authority source, including passkey unlinking/replacement and
      OIDC/SAML authority unlinking once those methods move beyond modeled post-alpha
      contracts. This is future method work, not a gap in the current reset, rotation,
      regeneration, addition, replacement, removal, recovery reset, or identifier-change
      paths.
- [x] Define lower-core account or subject-auth-state deletion scheduling.
- [x] Define lower-core subject-auth-state deletion cancellation.
- [x] Define credential-reset pending action records.
- [x] Define long-wait pending action records for subject-auth-state deletion.
- [x] Define that delayed second-factor reset uses the existing credential-targeted
      `Reset` pending-action record rather than a separate pending-action family.
- [x] Define long-wait pending action records for delayed credential replacement
      scheduling.
- [x] Define credential-reset pending-action execution preconditions.
- [x] Define credential-reset pending-action cancellation preconditions and authenticated
      runtime facade, with PgBouncer-backed coverage proving a live session for another
      subject cannot cancel the pending reset action.
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
      the registered target-credential plugin. PgBouncer-backed coverage now proves a live
      session for another subject cannot cancel pending replacement, removal, or
      regeneration actions.
- [x] Define pending-action execution preconditions for subject-auth-state deletion.
- [x] Add Postgres runtime facades for delayed subject-auth-state deletion execution and
      authenticated cancellation, loading subject pending-action records internally and
      deriving cancellation authority from the current live session.
- [x] Define pending-action execution preconditions for other subject-targeted waits.
- [x] Define how second-factor reset is selected as a policy role over credential reset,
      without making it a separate credential kind.
- [x] Define admin/support recovery as a Paranoid-shaped verified intervention.
- [x] Define the lower-core approval-to-lifecycle-planning handoff for admin/support
      intervention: typed verified intervention, scoped lifecycle evidence, immediate vs
      delayed planning, support-specific audit, support-specific notice, and direct web
      runtime rejection.
- [x] Define private lower-core and Postgres runtime candidate storage/facades for
      admin/support recovery request, approval, denial, expiry, audit, notices, and
      immediate-vs-delayed lifecycle handoff over the verified intervention model.
- [x] Define mounted admin/support recovery product boundary: stored candidate scope,
      staff/support authorization callback shape, approval/denial/expiry flow, committed
      response surface, and no application access to verified interventions, lifecycle
      context, pending-action records, notices, revocation policy, or method work.
- [x] Implement private mounted admin/support Postgres service sequencing over that
      boundary: candidate request, staff-authorized approval/denial, callback rejection as
      no mutation, deadline-derived expiry, delegation through private runtime facades,
      committed outcome mapping, and PgBouncer-backed coverage proving support
      intervention requests cannot create candidate state or notices for a target
      credential that is not active for the submitted subject.
- [x] Implement private mounted delayed credential-lifecycle execution service for
      approved matured pending actions: derive the stored action from authoritative state,
      accept only bounded action-appropriate method payloads, dispatch reset, replacement,
      regeneration, and removal through private Postgres runtime facades, and expose only
      committed delayed execution outcomes.
- [x] Implement private mounted delayed subject-auth-state deletion execution and
      cancellation service: delegate to the private Postgres runtime, expose only
      committed subject-deletion outcomes, and route execution-time app-owned data
      lifecycle work through durable Queue-backed integration.
- [ ] Implement concrete public mounted admin/support recovery routes/services, durable
      queue-backed delivery integration, public staff-auth callback configuration, and
      user-visible rendering.
- [x] Define durable notices for credential reset authorization, delayed reset scheduling,
      and reset execution.
- [x] Define lower-core durable notices for non-reset pending replacement, removal, and
      regeneration execution/cancellation.
- [x] Define lower-core durable notices for subject-auth-state deletion scheduling,
      execution, and cancellation.
- [x] Define private, public-shaped mounted deletion integration, including how app-owned
      subject/account data deletion or disabling commits as a recoverable Queue-backed
      durable effect alongside auth-owned subject deletion execution and notices.
- [x] Wire private Queue dispatch for core durable effects so committed out-of-band
      message commands and security notifications are enqueued through Paranoid Queue with
      a permanent auth dispatch marker.
- [x] Wire private Queue worker handlers for core durable effects so queued out-of-band
      message commands and security notifications decode into typed delivery requests,
      call idempotent delivery integrations, and map success, retryable failure, permanent
      failure, and malformed payloads through Queue worker outcomes.
- [x] Pin mounted delayed credential lifecycle and subject-auth-state deletion security
      notices through the mounted Queue worker boundary.
- [x] Define durable notices for credential additions once add-credential transitions
      exist.
- [ ] Implement concrete public mounted deletion routes/services and user-visible
      rendering over delayed subject-auth-state deletion and app-owned data lifecycle
      integration.
- [x] Define which lifecycle mutations require immediate subject-wide revocation.
- [x] Define which lifecycle mutations require step-up freshness.
- [x] Define which lifecycle mutations require delayed execution.
- [ ] Add tests proving applications cannot mutate credential lifecycle state by calling
      lower-level storage helpers directly through the mounted API. Exit criteria: the
      final public mounted API exposes no storage or lower-command path that can mutate
      credentials, pending actions, lifecycle authority, method work, notices, revocation,
      or response effects outside the mounted runtime.

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
- [x] Implement the lifecycle/runtime path that generates and stores new user-visible
      recovery codes.
- [x] Give TOTP a stable configured-secret credential instance id.
- [x] Implement real direct TOTP using the selected mature crate through a Paranoid-owned
      RFC-6238 wrapper.
- [x] Implement challenge-bound TOTP Bloom fast-fail as a real first-party method lane.
- [x] Add cookie-budget tests for challenge-bound TOTP Bloom filters.
- [x] Add false-negative safety tests for challenge-bound TOTP Bloom filters.
- [x] Implement password-derived message-signature auth.
- [x] Define password salt/verifier construction.
- [x] Define canonical signed message format for password-derived signatures.
- [x] Seal verifier material into the message-signature challenge when safe.
- [x] Recheck authoritative verifier/version after message-signature pre-state success.
- [x] Bind password-derived weak-proof gate verification to the exact challenge state and
      submitted response payload.
- [x] Keep WebAuthn/passkey contract hooks modeled for post-alpha implementation.
- [x] Keep OIDC contract hooks modeled for post-alpha implementation.
- [x] Keep SAML contract hooks modeled for post-alpha implementation.
- [ ] Decide whether deterministic email OTPs are a separate helper or out of scope.
- [ ] Keep SMS/postal out-of-band method scope post-alpha unless a later product decision
      moves one forward.

## Phase 6: Finish Storage, Schema, And Durable Effects

This phase turns the executable model into a production Postgres subsystem.

Phase 6 exits when the final public-alpha auth table set is registered, migrated,
validated, covered through PgBouncer transaction-mode tests, and pinned for byte-stable
schema semantics plus operation counts on hot paths.

- [x] Build Postgres runtime slices for core session, trusted-device, active-proof, and
      selected method paths.
- [x] Route Postgres auth paths through transaction-pooler-safe query helpers.
- [x] Store internal identifiers and secrets with byte-stable database semantics.
- [x] Commit method-owned state atomically through registered method work.
- [x] Add auth-specific source guards for production auth Postgres code covering portable
      query constructors, raw pool bypasses, session-level Postgres features,
      transaction-local `set_config`, database-owned time, and schema-version ordering.
- [x] Finish concrete Postgres auth schema. Exit criteria: every public-alpha core and
      method-owned table family is centralized in the schema contract, mapped from storage
      targets without sampling gaps, and validated against adopted existing tables.
      `auth_bootstrap_facade_uses_db_foundation_schema` now asserts the exact core plus
      public-alpha first-party method table set created by bootstrap.
- [x] Finish auth migration execution and validation. Exit criteria: auth bootstrap runs
      after DB foundation bootstrap, validates physical core and registered method schemas
      before recording the component ledger row, revalidates recorded schema state, and
      has real upgrade and malformed-adoption coverage.
      `postgres_store_migrate_schema_upgrades_previous_auth_schema_ledger_version` pins
      the recorded-version upgrade path, and
      `postgres_runtime_rejects_malformed_adopted_method_schema_before_recording_ledger`
      pins method physical validation before ledger trust.
- [x] Make the core auth Postgres store derive from Paranoid's DB foundation: DB bootstrap
      schema, shared schema ledger, and schema-local core table names.
- [x] Make first-party Postgres method configs derive schema-local method table names from
      the DB foundation schema by default.
- [x] Route auth-core schema ledger migration and validation through Paranoid's
      public-shaped component schema API, while preserving auth-owned physical schema
      validation before the component version is recorded.
- [x] Build the private WIP auth bootstrap facade that runs after DB foundation bootstrap,
      constructs the core store plus registered method plugins from one DB bootstrap
      config, and performs auth migration or validation without application-managed table
      choreography.
- [x] Add end-to-end auth bootstrap tests proving the facade uses the shared DB foundation
      schema ledger, schema-local core/method tables, transaction-pooler-safe SQL, and no
      auth advisory-lock path.
- [x] Pin operation counts for hot auth paths once schema is less fluid. Exit criteria:
      every public-alpha hot path has an exact database-operation sequence assertion,
      route layers prove they do not add storage work beyond the owned runtime
      transaction, and durable-effect worker paths have bounded dispatch/delivery
      sequences.
- [x] Integrate core auth durable effects with Paranoid Queue through a private dispatch
      boundary.
- [x] Integrate core auth durable effects with Paranoid Queue through private worker
      handlers that expose committed delivery requests to callbacks without exposing auth
      internals.
- [x] Integrate method-owned durable effects with Paranoid Queue through the method
      registration contract.
- [x] Integrate app-owned subject data lifecycle effects with Paranoid Queue through the
      mounted subject-deletion and durable-effect worker boundary.
- [x] Commit core durable effect commands atomically with auth transitions.
- [x] Commit every method-owned delivery command atomically with the auth or method
      transition that created it.
- [x] Commit app-owned subject data lifecycle requests atomically with subject-auth-state
      deletion execution.
- [x] Map core out-of-band and security-notification delivery callback outcomes to Queue
      success, retry, and dead-letter behavior.
- [x] Add mounted/operator visibility and stale-running recovery coverage for auth
      delivery workers once the mounted worker configuration exists.
- [x] Add registration coverage for every current method-owned table schema, validation,
      preconditions, mutations, and durable effects without bypassing core invariants.
- [x] Remove any auth DB tests that skip when a database resource is missing; missing
      required resources must fail loudly in the final gate.
- [x] Add PgBouncer transaction-mode coverage for every production auth storage path. Exit
      criteria: every production storage path is exercised through real PgBouncer
      transaction mode, including direct runtime, mounted route, dispatch, worker, and
      bootstrap/migration paths.
- [x] Add schema-validation tests for byte-stable and collation-safe auth tables. Exit
      criteria: every final public-alpha core and method-owned auth table rejects missing
      constraints, missing required indexes, unexpected columns, default-collation
      correctness text, and byte-length/domain drift in adopted schemas.

## Phase 7: Build Web Transport And Mounted Runtime

This phase is the public product surface. It should consume the lower layers, not expose
them.

Phase 7 exits when the public mounted backend is a coherent Tower/http-first product
surface: one configuration object, one mount-path-bound auth route service, protected
route layers, app-subject mapping, durable-effect worker construction, route manifest,
cookie/CSRF ownership, public response vocabulary, and no exposed lower-core ceremony
helpers.

- [x] Model response materialization for cookies.
- [x] Model web transport boundary for cookies and CSRF cycling.
- [x] Define mounted-route input limits for every auth request type.
- [x] Add mounted-runtime tests proving malformed mounted-route inputs reject before
      storage work where possible.
- [x] Add tests proving oversized mounted-route inputs fail loudly without truncation,
      fallback, or implementation-shaped tolerances.
- [x] Add cookie-size budget tests for every auth cookie family: session, trusted-device,
      active-proof challenge, and active-proof continuation. The web transport now rejects
      any auth `Set-Cookie` header over the single-cookie budget instead of emitting an
      unusable oversized cookie.
- [ ] Design the public mounted auth facade.
- [ ] Design the public auth configuration object. Exit criteria: one config owns storage,
      methods, weak gates, cookies, CSRF, lifecycle policy, durable integrations, app
      hooks, route setup, and mount path, then rejects incomplete mutation/recovery
      surfaces at construction. Current private foothold: `PostgresAuthSystemConfig` now
      owns DB bootstrap config, credential secret material, mounted runtime config, method
      setup, route setup, weak gates, web transport, mount path, and durable integrations
      before building `PostgresAuthSystem`. Construction-time validation now rejects
      configured mounted route families unless the registered method plugins expose the
      exact route capabilities those families need. Final public names, visibility,
      app-hook placement, and the full public config vocabulary remain open under this
      item.
- [ ] Design route registration or handler construction. Exit criteria: the public route
      manifest is config-derived, mount-path-bound, method-aware, body-limit aware, and
      does not require applications to inspect lower ceremony or lifecycle config
      directly. Current private foothold: the mounted route guard now resolves requests
      through the config-derived manifest descriptor before CSRF verification or body
      collection, and the HTTP service uses that same descriptor for the route-specific
      body limit. Final public names and exposure remain open under this item.
- [ ] Design public route response vocabulary and rendering. Exit criteria: mounted route
      responses expose stable public outcome kinds and only public fields; internal
      runtime outcomes, subject ids, session ids, credential-instance ids, pending-action
      ids, proof summaries, and response-effect sequencing remain unavailable to
      application route code. Current private foothold: mounted route rendering now uses
      an explicit `MountedAuthPublicRouteResponseKind` vocabulary for every emitted JSON
      `type`, and tests pin uniqueness plus the currently rendered user-visible outcome
      families. Final public type names and packaging remain open under this item.
- [ ] Design the public credential inventory and opaque handle surface for authenticated
      lifecycle routes. Exit criteria: applications get Paranoid-owned credential handles
      and safe metadata for the authenticated subject without querying auth tables or
      inventing lifecycle target handles themselves. Current private foothold:
      authenticated credential inventory returns `credential_handle_base64url`, and
      authenticated reset, replacement, removal, regeneration, and rotation route bodies
      consume `credential_handle_base64url` rather than credential-instance-id fields.
- [ ] Design middleware construction. Exit criteria: the public mounted surface exposes
      combined protected-route and app-subject mapping layers that resolve Paranoid auth
      state, enforce route requirements before app service execution, and do not expose
      lower composition pieces as the normal app boundary. Current private foothold:
      combined protected-route and app-subject mapping layers are constructed from
      `MountedAuthProtectedRoutePolicy`, whose named constructors pair request kind with
      the required auth posture instead of asking route code to pass those facts as loose
      parameters.
- [x] Design route-level auth requirements. Authenticated-subject and fresh-step-up
      requirements are enforced by the combined protected mounted-route layers. Unit
      coverage still proves the standalone internal requirement checker rejects missing
      mounted request state, rejects unauthenticated states with typed outcomes, rejects
      stale authenticated sessions for fresh-step-up routes, allows non-step-up-fresh
      authenticated sessions for authenticated-subject routes, and allows only fresh
      authenticated sessions for fresh-step-up routes. Final public configuration names
      and route integration remain part of the broader public mounted API work.
- [x] Design application subject mapping hooks. The mounted surface has a combined
      protected application subject mapping layer that runs only after Paranoid request
      resolution and route-requirement enforcement, calls an app-owned mapper with
      Paranoid-owned subject/session facts, inserts typed app-owned subject context into
      request extensions, and rejects unauthenticated states before the mapper runs. Unit
      coverage still pins the standalone internal mapping checker. Final public
      configuration names and integration into the one-config mounted product remain part
      of the broader public mounted API work.
- [x] Design durable integration callbacks without letting apps sequence auth ceremonies.
      The mounted runtime config owns durable-effect integrations once, and the mounted
      worker service builds core plus method Queue handlers from that config. Application
      callbacks receive only committed delivery/app-data lifecycle requests from Queue;
      they do not construct auth ceremonies, method work, Queue payloads, notices,
      revocation choices, proof facts, or response effects at request time.
- [x] Build the private runtime and mounted-service no-session recovery-code ceremony that
      creates, binds, and completes a `RecoverOrReplaceCredential` active-proof attempt
      before calling the private unauthenticated reset scheduling or execution lanes.
- [x] Shape the private mounted no-session recovery service around a configured flow so
      route code can call start, proof completion, delayed reset scheduling, and immediate
      reset execution without accepting target credential ids, lifecycle authority facts,
      method work, or proof sufficiency claims from application requests.
- [x] Add mounted no-session recovery input constructors for submitted recovery proof
      material and reset method payloads so route parsing goes directly through the
      bounded, redacted wrapper types before reaching runtime inputs. The route request
      constructors now accept time plus preflight/raw request bytes and construct the
      lower mounted inputs internally, so route-shaped code does not pass prebuilt
      recovery-proof or reset-payload wrappers.
- [x] Add private mounted no-session recovery route-shaped outcomes and step policy so
      future route code does not expose attempt ids, proof summaries, failure deletion
      flags, subject ids, or target credential ids. Start requires challenge-issue
      preflight, proof completion requires submitted recovery secret material, and
      continuation-cookie reset scheduling/execution require CSRF. The private mounted
      service now exposes one route request executor for those steps, so route-shaped
      callers do not select lower per-step helpers directly. That executor verifies real
      Paranoid CSRF request state before scheduling or executing no-session recovery reset
      work, missing CSRF rejects before storage work, and the normal executor returns only
      the route response plus rendered `Set-Cookie` headers. Tests that need lower runtime
      details must use the separately named internal inspection path.
- [x] Add typed private no-session recovery HTTP request bodies so route-shaped code
      passes only bounded start/proof/reset body material and the mounted service
      constructs lower route requests internally. The transitional erased any-step body
      path has been removed; endpoint-shaped code now enters through route-specific body
      types.
- [x] Add route-specific private no-session recovery HTTP request body types and service
      entry points for start, proof submission, delayed reset scheduling, and immediate
      reset execution, so endpoint-shaped code does not need to carry an erased any-step
      recovery body. Postgres route tests now exercise the step-specific start, proof,
      schedule, and execute entry points while keeping internal runtime inspection behind
      the separately named test-only path.
- [x] Add a narrow configured private no-session recovery route service that owns the
      recovery proof method and reset target method, so endpoint-shaped code calls
      start/proof/schedule/execute without passing method config, target config, lower
      route requests, lifecycle authority, or method work on each request.
- [x] Add a user-visible private no-session recovery route response body projection so
      endpoint rendering can use committed results without seeing runtime execution, proof
      internals, subject ids, target credential ids, or the internal pending-action id
      created for delayed reset scheduling.
- [x] Add a private no-session recovery endpoint handler that selects the configured route
      by HTTP method and path, requires the typed body to match that route's step, rejects
      unknown routes or mismatched bodies before CSRF or auth storage work, and returns an
      `http::Response` carrying only the user-visible route body plus rendered
      `Set-Cookie` headers.
- [x] Add a private mounted auth route service with an explicit mount path, top-level
      route response enum, route dispatch to configured no-session recovery endpoints, and
      no-storage-work rejection for unknown mounted routes.
- [x] Add a private mounted auth submitted-body boundary that selects the configured route
      before body validation, rejects route/body mismatches before CSRF or storage work,
      converts submitted no-session recovery material into bounded typed route bodies
      inside Paranoid, and keeps target credentials, lifecycle authority, method work, and
      proof-sufficiency facts out of endpoint-shaped code.
- [x] Add a private collected-HTTP-body parser for the configured no-session recovery
      routes: route selection happens before body parsing, JSON routes require
      `Content-Type: application/json`, byte payload fields use canonical base64url, the
      delayed reset scheduling route stays empty-body, CSRF-required reset routes verify
      CSRF before body parsing or storage work, malformed bodies on non-CSRF routes reject
      before storage work, and the PgBouncer-backed mounted route test exercises the
      parser.
- [ ] Build the public no-session recovery route/service surface over that private
      ceremony. Exit criteria: the public surface selects routes before body work,
      verifies CSRF before body collection where required, applies route-specific body
      limits, renders only public recovery responses and committed cookies, and covers
      unknown-route, malformed-body, oversized-body, missing-CSRF, accepted, rejected,
      delayed-reset, and immediate-reset paths through the mounted HTTP service.
- [ ] Expose mounted APIs that prevent apps from setting or assembling auth cookies
      manually. Exit criteria: production route code sees only committed `Set-Cookie`
      headers and public route outcomes; lower runtime executions remain inspection-only
      and no route family exposes cookie assembly or response-effect ordering to
      applications. Current private foothold: the mounted HTTP route service now calls one
      rendered-response route boundary that returns `Response<Vec<u8>>` with committed
      `Set-Cookie` headers already applied; the lower typed route response body and route
      dispatcher are sibling-private implementation details, and the unused aggregate
      submitted-body dispatcher has been removed.
- [ ] Expose mounted APIs that prevent apps from deciding proof sufficiency manually. Exit
      criteria: public routes accept only route-selected request material and Paranoid
      cookies/CSRF; proof acceptance, rejection, summaries, attempts, and continuation
      state are derived inside Paranoid and projected only as public route outcomes.
      Current private foothold: full-authentication out-of-band proof submission now
      routes through a dedicated committed route projection, including pre-state fast-fail
      rejection with no runtime execution, so route dispatch does not translate lower
      proof-verification internals into accepted/rejected responses inline.
- [ ] Expose mounted APIs that prevent apps from enqueueing required auth notices
      manually. Exit criteria: committed core, method-owned, and app-subject-data
      lifecycle effects flow through the mounted durable-effect worker and Queue handlers
      built from mounted config; route-shaped code cannot enqueue notices or delivery jobs
      directly.
- [ ] Wire automatic CSRF behavior for every auth route that needs it. Exit criteria:
      every advertised CSRF-required route verifies CSRF immediately after route selection
      and before body collection, body parsing, storage work, response cookies, staff
      authorization, or external callbacks.
- [x] Cycle CSRF tokens on session creation, logout, step-up, and other session-security
      mutations. Reducer-level guard coverage pins the exact transition classes that do
      and do not cycle CSRF. Web-transport coverage proves CSRF response effects render as
      bounded `Set-Cookie` headers. PgBouncer-backed Postgres runtime coverage now proves
      full authentication, trusted-device silent revival, trusted-device active-proof
      revival, step-up completion, logout, stale revoked-session clearing, and
      subject-wide revocation all render the expected CSRF cookie after committed storage
      work.
- [x] Add end-to-end mounted-runtime tests proving response cookies are rendered only
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

- [x] Build the immutable audit-event coverage matrix for every security-significant auth
      transition.
- [x] Add tests proving safe-read cache hits are not recorded as lifecycle audit events.
- [ ] Add tests proving public identifier flows do not reveal whether an email, account,
      method, or identifier exists.
- [ ] Add tests proving user-facing responses stay indistinguishable across registered and
      unregistered identifiers where policy requires it. Exit criteria: public mounted
      responses and cookie effects are indistinguishable for every configured
      identifier/proof flow where enumeration resistance is required, while preserving the
      intended no-storage fast-fail boundaries.
- [x] Define the public `SubjectId` boundary so auth does not model organizations, billing
      accounts, resource ownership, route authorization, or app-specific identity shapes.
- [x] Define display metadata boundaries for user-agent strings.
- [x] Define IP-address boundaries so IPs remain infrastructure guardrails, not auth-core
      identity signals.
- [x] Add tests proving IP addresses are not required as auth-core identity inputs.

## Phase 10: Write Public API And Docs

This phase should be late. Public docs should describe the actual mounted system, not an
intermediate planning model.

- [ ] Remove private-WIP dead-code and unused-import allowances before exposing any auth
      API.
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
