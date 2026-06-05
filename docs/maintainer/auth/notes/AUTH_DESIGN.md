# Auth Design

This is the canonical maintainer note for the current Paranoid auth design. It is not a
published user-facing spec. It exists so auth work can survive context compaction without
requiring agents to triangulate across stale audit notes.

The raw notes in `docs/maintainer/auth/raw-notes.local/` are source material, not
implementation instructions. They contain sketches, old code, rejected directions, and
inconsistent branches. Use them to understand design intent, but do not silently copy them
or silently diverge from them.

## Source Discipline

When auth notes conflict, use this order:

1. Live code and tests for what currently exists.
2. Current maintainer decisions captured in this document.
3. Raw notes in `docs/maintainer/auth/raw-notes.local/` for original design intent.

Do not revive deleted audit notes as parallel sources of truth. If this document is wrong
or incomplete, update this document.

## Status Language

This document records both final design decisions and WIP implementation status. Keep
those separate:

- **Decided** means the design direction is intentional and future work should preserve it
  unless the maintainer explicitly reopens the decision.
- **Modeled** means the lower-core vocabulary or reducer shape exists, but the production
  runtime path may still be incomplete.
- **Implemented** means live code exists for the named path.
- **Pinned** means tests prove the semantic guarantee, including operation-count or
  no-storage-work claims where that is part of the guarantee.

The fast-fail thesis is not pinned merely because a challenge cookie, Bloom filter, method
hook, or matrix row exists. A row is pinned only when live tests prove the claimed
pre-state rejection boundary and the authoritative post-gate boundary.

## Core Thesis

Paranoid auth is app-owned authentication infrastructure. It should support app-to-user
auth rather than forcing app-to-provider-to-user auth.

The system should be high-level and hard to misuse. Applications should not assemble
security-sensitive cookies, claim proofs are verified, decide when to write audit events,
or manually orchestrate storage preconditions. The lower core is an opinionated planner.
The Paranoid-owned runtime, storage adapter, method plugins, cookie layer, and queue
integration execute that plan.

The central security invariant is:

```text
Fail fast, never succeed fast.
```

Stateless material may prove that a request is hopeless and should be rejected before
authoritative storage work. Stateless material must not grant authentication by itself.
Successful stateless checks only permit the runtime to continue to authoritative state.

Fast-fail is not a small optimization. It is a load-shedding and denial-of-service
resilience invariant. The design should actively look for safe protocol shapes that reject
bad traffic before database work.

## Final Product Shape

The intended public auth product is not a bag of low-level auth helpers. The intended
shape is a Paranoid-owned auth system that applications configure and mount.

An application should be able to provide one clear configuration object that names:

- the auth methods it wants to support;
- the database connection settings;
- durable effect integrations such as send-email, send-SMS, webhook, queue, or security
  notification callbacks;
- route, cookie, CSRF, origin, redirect, and application URL policy;
- method-specific policy such as trusted-device windows, step-up requirements, recovery
  rules, deletion waits, and admin/support intervention rules;
- application hooks for mapping Paranoid subjects to app-owned records where needed.

From that configuration, Paranoid should construct the full auth runtime: middleware,
endpoint handlers, cookie handling, CSRF cycling, challenge issuance and completion,
session/trusted-device lifecycle, credential lifecycle, durable effect enqueueing, audit
events, and storage migrations or validation. The configuration may be rich, but it should
be explicit, robust, and difficult to misuse.

Applications should not have to assemble auth ceremonies route by route, set
security-sensitive cookies by hand, decide when a proof is sufficient, remember to enqueue
notices, or know which state preconditions must be locked. Applications provide business
integration points and authorization decisions. Paranoid owns authentication sequencing
and security invariants.

This product shape is a design constraint on the lower layers. The reducer, runtime,
storage adapter, method plugins, web transport, and durable effect system should compose
into one coherent mounted auth system. If a lower-layer API would require applications to
manually orchestrate security-sensitive auth steps, the lower-layer shape is wrong even if
the reducer transition itself is correct.

Public alpha should be framework-neutral Tower/http-first, with no Axum dependency and no
Axum-specific adapter in Paranoid. Paranoid should expose a mounted auth runtime as
ordinary HTTP/Tower services and layers:

- an endpoint service that owns auth routes under an application-mounted base path;
- a request/session resolution layer that inserts Paranoid auth state into request
  extensions;
- high-level policy layers or handles for route/session/step-up requirements where needed;
- one mounted configuration object for methods, storage, cookies, CSRF, durable effects,
  lifecycle policy, proof policy, and app integration hooks.

Applications may mount those services through Axum, Vorma, another framework, or raw Tower
composition, but Paranoid must not require the application to perform body conversion,
cookie assembly, CSRF choreography, proof sufficiency checks, challenge sequencing, or
response-effect ordering. Any ugly body typing or service plumbing belongs inside
Paranoid. The user-facing API should be a small mounted runtime with clear
services/layers, not framework-specific helpers and not low-level ceremony pieces.

## Planner And Runtime Boundary

The lower auth core:

- owns lifecycle and proof-semantics invariants;
- performs no I/O;
- does not set cookies, send messages, write database rows, or dispatch jobs;
- reduces loaded state plus a command into an atomic transition plan;
- emits abstract commit work and response effects.

The runtime and adapters:

- decode and encode cookies;
- generate fresh identifiers and secret material for newly created core records;
- verify pre-state-load gates;
- derive load contracts;
- load authoritative state;
- call the reducer;
- enforce preconditions in one transaction;
- materialize fresh secrets;
- commit core mutations, method work, audit events, and durable effect commands;
- release response effects only after commit succeeds.

Applications provide business facts and callbacks. They should not be trusted to perform
auth sequencing correctly.

Applications also should not preselect identifiers for newly created auth records. The
reducer may receive generated IDs as internal command material, but the runtime facade
owns generation for sessions, trusted-device credentials, active-proof attempts, and
active-proof challenges.

The generic runtime/model paths are private scaffolding for reducer and boundary tests,
not the intended production substrate. Public auth should mount through a concrete
Paranoid-owned Postgres runtime that consumes the lower core, DB foundation, method
registry, cookie/CSRF primitives, and durable-effect queue integration. This follows the
repo-wide Postgres-only direction and avoids letting applications or arbitrary adapters
own security-sensitive auth sequencing.

The private generic and Postgres web runtimes share one exhaustive direct-command
admissibility guard. Commands that require runtime-owned fresh ids, continuation-cookie
validation, method/plugin dispatch, lifecycle-authority loading, method-owned commit work,
challenge-cookie construction, or pending-action loading are rejected before cookie
decode, state load, or commit. Only request-shaped facades should construct those commands
for web execution.

## Database-Authoritative Success

The database is authoritative for positive auth decisions, with one explicit exception:
bounded safe-read cache state may satisfy safe read-only requests for a short configured
window after recent DB validation.

Cookies may carry:

- encrypted handles;
- fresh bearer secrets;
- active-proof continuation handles;
- expiry ceilings;
- recently validated safe-read state;
- challenge context;
- fast-fail verifiers.

Cookies must not by themselves prove that:

- a session is still valid;
- a trusted device is still trusted;
- a subject was not revoked;
- a state-changing or sensitive request may proceed;
- a proof succeeded.

## Session And Trusted-Device Lifecycle

The core-known lifecycle objects are sessions, session credentials, trusted-device
credentials, active-proof attempts, active-proof continuation credentials, active-proof
challenges, subject auth-state rows, audit events, and durable effect commands.

Session and trusted-device cookies carry `id + secret`. Storage keeps MACs of secrets, not
plaintext bearer material. A leaked database row should not itself become a bearer token.

The same principle applies to active-proof attempts if an attempt can be resumed across
multiple requests. A naked attempt id is not a sufficient continuation credential for a
satisfied proof stack. Either the runtime must fuse completion into the final lifecycle
transition, or it must issue an encrypted continuation cookie carrying attempt id plus
fresh secret material whose MAC is stored with the attempt. Full authentication, step-up,
and trusted-device active revival must not become "whoever knows the attempt id can
finish" transitions.

### Active-Proof Continuation

An active-proof attempt is a server-side proof stack, not a session. But while it is open,
it is still a security-sensitive continuation handle. The browser should continue an
attempt by presenting a Paranoid-owned continuation credential, not by submitting a naked
attempt id in JSON.

The intended shape is:

1. Starting an attempt creates an attempt row and a fresh continuation secret.
2. Storage stores only a MAC of that continuation secret.
3. The response sets an encrypted active-proof continuation cookie carrying attempt id,
   proof use, optional subject id for already subject-bound attempts, deadline, and the
   fresh secret.
4. Challenge issue, configured-secret completion, full-authentication completion, step-up
   completion, and trusted-device active revival derive the attempt id from this cookie.
5. The runtime can reject an expired or malformed continuation cookie before DB.
6. Authoritative success still loads the attempt row, compares the continuation secret
   MAC, validates proof-stack policy, and enforces subject revocation.
7. When the attempt is closed or deleted, the runtime clears the continuation cookie.

Challenge cookies remain proof-specific ceremony cookies. They can carry challenge id,
nonce, fast-fail MACs, Bloom filters, or method-specific sealed state. They do not replace
the attempt continuation credential unless a flow is deliberately fused so proof
completion and finalization happen in one runtime transaction.

Trusted devices are core-known because they have lifecycle-specific powers:

- silent session revival inside the configured revival window;
- reduced active-proof requirements after the silent window but before device expiry;
- credential rotation;
- targeted revocation;
- participation in logout and subject-wide revocation.

The lifecycle model preserves the `7.txt` intent:

- session refresh happens only in the refresh window, not on every request;
- token ceilings can fast-fail impossible requests;
- DB state accepts, refreshes, revives, and revokes;
- trusted-device revival is separate from session refresh;
- subject-wide revocation must be checked before stateful success.

The previous-secret grace window is a concurrency grace only. It must be configured as a
short bounded race window, not as a second refresh lifetime. Active sessions refresh only
inside the configured refresh window. Requests before that window may reissue a
safe-read-capable cookie after authoritative validation, but they must not rotate session
secrets, cycle CSRF, or write session refresh state. Stale previous secrets are accepted
only through authoritative state while inside the grace deadline. Once the grace deadline
has passed, a structurally valid cookie for an otherwise live record trips the mismatch
policy instead of silently extending the old credential.

### Tripwire Policy

Paranoid's live model uses rotating credential secrets with MACs stored in authoritative
state. Session and trusted-device cookies carry an id, secret, and secret version.
Authoritative storage classifies the presented secret as:

- current;
- previous within the configured concurrency grace window;
- previous after that grace window;
- unknown.

This is a deliberate hardening beyond the older strict version-counter sketch. It keeps
database rows from becoming bearer credentials and lets sessions, trusted devices, and
active-proof continuation credentials share the same possession-proof shape.

Tripwire is not generic cookie rejection. Missing cookies, malformed encrypted cookies,
expired cookie ceilings, missing records, expired records, and already-revoked records are
rejected or cleared without tripwire. Those requests cannot produce access from that
credential.

Tripwire applies only when a request presents a structurally valid Paranoid cookie for an
otherwise live authoritative session or trusted-device record, but the presented
credential secret is no longer acceptable:

- previous after grace;
- unknown.

For a session tripwire, Paranoid revokes that session record with
`RevocationReason::Tripwire`, clears the session cookie, audits the mismatch and
revocation, and cycles CSRF. If that session is associated with a trusted-device
credential, Paranoid also revokes that trusted-device credential and clears the
trusted-device cookie because the browser/device context has evidence of compromise.

For a trusted-device tripwire, Paranoid revokes that trusted-device credential with
`RevocationReason::Tripwire`, clears the trusted-device cookie, and audits the mismatch
and revocation.

Tripwire does not perform subject-wide mass logout by default. That preserves the original
"kill the compromised session" spirit while extending it to the associated device token
when there is evidence that browser/device context is compromised.

## Proof Policy Model

Auth policy has four distinct layers:

1. **Generic primitive**: the reusable mechanism shape, such as a sealed challenge cookie,
   MAC verifier, signed message, Bloom filter, bearer credential, or durable effect
   command.
2. **Proof family**: what security fact a proof intrinsically establishes, such as message
   signature, out-of-band code, shared-secret OTP, origin-bound public key, or federated
   identity assertion.
3. **Plugin method**: the concrete implementation that produces the proof, such as
   password-derived signature, SSH signature, email OTP, TOTP app, WebAuthn passkey, or
   OIDC Google.
4. **Lifecycle/policy transition**: what job a proof is doing inside a ceremony, such as
   binding an active-proof attempt to a subject, contributing to full authentication,
   reviving a trusted device, satisfying step-up, or confirming a destructive action.

These layers must not collapse into each other. A concrete plugin must never reshape the
generic primitive layer or force the lower core to split a proof family merely because one
method has special setup needs. Likewise, a generic primitive must not be treated as a
complete auth factor by itself. The core vocabulary should be stable enough that many
plugins can share the same family and primitive shape while still declaring their
method-specific risk and authoritative checks.

Examples of generic primitives:

- encrypted challenge cookie;
- response MAC verifier;
- signed-message challenge;
- challenge-bound Bloom definite-miss filter;
- rotating bearer credential;
- durable effect command.

Examples of proof families:

- out-of-band code;
- message signature;
- shared-secret OTP;
- origin-bound public key;
- federated identity assertion;
- passive rotating bearer credential;
- one-time recovery credential.

Examples of plugin methods:

- `email_otp`;
- `sms_otp`;
- `password_derived_signature`;
- `ssh_signature`;
- `bitcoin_signature`;
- `ethereum_signature`;
- `solana_signature`;
- `totp_app`;
- `webauthn_passkey`;
- `oidc_google`;
- `saml_enterprise`.

Examples of lifecycle/policy transition roles:

- bind an active-proof attempt to a subject;
- contribute to full authentication;
- revive a trusted device after the silent revival window;
- satisfy step-up freshness;
- recover or replace a credential;
- confirm a sensitive or destructive action.

The core should not use additive proof scores. Scores hide why a proof stack is valid and
make incoherent mixes look acceptable. Policies should be transition-specific proof-stack
requirements inside a core-validated vocabulary.

## Public Alpha Method Set

Public alpha should include these first-party methods and lifecycle primitives:

- email OTP as the first out-of-band code method;
- password-derived message signature as the first message-signature method;
- trusted-device lifecycle;
- TOTP as the first shared-secret OTP method;
- recovery codes as the first one-time recovery credential method.

TOTP alpha includes both lanes:

- direct known-subject TOTP, where another credential or active proof has already fixed
  the subject and the weak gate is the only pre-state rejection gate;
- challenge-bound TOTP Bloom fast-fail, where the runtime issues an encrypted challenge
  cookie containing a Bloom filter that can reject definite non-matches before DB work.

The Bloom lane fits the core thesis: false positives are acceptable because they only
continue to authoritative verification, while false negatives are not acceptable. The
implementation must therefore test no-false-negative behavior for the encoded challenge
window and must budget cookie size explicitly.

WebAuthn/passkeys, OIDC, SAML, SMS OTP, postal out-of-band codes, and concrete
blockchain/wallet signature plugins are post-alpha method scopes unless a later product
decision moves one into alpha. The proof families and plugin contracts should still leave
room for them.

Non-overridable safety rules include:

- a passive trusted-device proof cannot satisfy step-up by itself;
- online-guessable proofs require a weak-proof gate and failure-budget rules;
- known-subject-only proofs cannot bind an unbound active-proof attempt;
- one-time proofs must commit method-owned consumption work atomically with success;
- a single credential instance must not count twice inside one proof stack;
- subject context supplied by a trusted device or prior proof must match the transition
  subject.

## Credential Lifecycle And Recovery Policy

Credential lifecycle is core auth policy, not application glue. If applications are left
to assemble email changes, password resets, second-factor resets, account deletion waits,
or support/admin recovery flows, they can accidentally collapse multiple apparent factors
into one effective factor.

The core identity anchor is `SubjectId`. A subject is the auth principal Paranoid
protects. The core must not know whether the application calls that principal a user,
member, account, tenant actor, email account, wallet account, or something else.
Applications may map subjects to resource ownership, organizations, billing accounts, or
profiles outside auth. Paranoid-owned auth state should reason about subject credentials
and credential lifecycle, not application authorization.

A credential is not just a proof method label. For lifecycle policy, the core needs a
credential vocabulary at roughly this shape:

- credential family: message signature, out-of-band identifier, shared-secret OTP,
  origin-bound public key, federated identity assertion, recovery code, trusted device;
- credential method: password-derived signature, email OTP to a specific identifier, TOTP
  app, WebAuthn passkey, OIDC provider, etc.;
- credential instance: the concrete password verifier, email identifier, TOTP secret,
  passkey credential id, recovery-code set, trusted-device credential, or provider
  binding;
- recovery authority: what other credentials or external authorities can reset, replace,
  disable, or create this credential;
- lifecycle state: active, pending addition, pending replacement, pending removal,
  scheduled deletion, consumed, revoked, expired, superseded, admin-suspended.

The important invariant is proof independence. A proof stack must not count as
multi-factor merely because it names two methods. It must count only if the factors are
independent for the transition being attempted.

Examples:

- If a password-derived signature credential can be reset by email OTP alone, then
  password plus that same email OTP is not two independent factors for high-risk recovery.
- If a password-derived signature credential can be reset through email alone with no
  independent second factor and no waiting period, then password auth is effectively a
  convenience bypass for email OTP. It should not be counted as an independent factor from
  that email path.
- Password reset by email-only recovery can be immediate only when the subject has no
  stronger independent credentials. If the subject does have stronger independent
  credentials but presents only email control, reset must become a delayed pending action.
  The exact delay is configurable policy, but the delay itself is part of preserving
  factor independence and account availability.
- If TOTP can be reset by an active session alone, then TOTP should not be treated as a
  durable second factor against session theft for the reset transition.
- If a support/admin action can replace a factor without a waiting period or user-visible
  notification, then the admin path is part of the effective recovery authority for that
  factor.
- If an OIDC provider controls the email identifier used to recover another factor, the
  provider assertion and that email path may be coupled for some policies.
- If recovery codes are generated only after a strong authenticated ceremony and consumed
  one time, they can be an independent recovery credential, but they must not also be
  resettable by the weak factor they are meant to rescue.

### Password Reset Non-Degradation

Password reset policy must preserve the subject's current effective authentication
strength. It is not enough to ask whether email can reset a password in isolation. The
policy must ask what credentials the subject already has and whether the reset ceremony
would downgrade that subject.

If the subject has only one effective factor, such as email OTP, then immediate email-only
password reset does not weaken the account. Paranoid would already allow that subject to
authenticate with email OTP alone. In that case a password-derived signature is a
convenience credential over the same recovery authority, not an independent second factor.

If the subject has independent active credentials, immediate email-only password reset
does weaken the account. Examples of independent credentials for this transition include a
valid trusted-device credential, TOTP, recovery code, SMS OTP when configured as a second
factor, passkey/WebAuthn credential, or another accepted independent proof source. The
exact accepted set is transition policy, but the invariant is fixed: a subject with
stronger configured auth should not be instantly downgraded by clicking "reset password"
from an untrusted environment and proving only email control.

For those stronger subjects, password reset must either:

- include an accepted independent proof, such as a valid trusted-device credential, TOTP,
  recovery code, or configured second factor; or
- become a delayed pending action with durable notice, cancellation policy, expiration,
  and atomic execution preconditions.

A trusted-device credential can count as independent possession evidence for password
reset non-degradation when it is valid, unrevoked, and accepted by the transition policy.
That does not imply a passive trusted-device proof can satisfy step-up or destructive
actions by itself. Each transition decides what the credential is allowed to do, but reset
policy must not pretend trusted-device possession is irrelevant when it is part of the
subject's current effective auth strength.

This suggests a second policy layer alongside `ProofPolicy`:

- `ProofPolicy` decides which proof stacks satisfy a transition once the proofs exist.
- Credential lifecycle policy decides whether those proofs are independent enough for the
  specific mutation: add credential, replace credential, remove credential, reset
  credential, schedule deletion, cancel deletion, revoke sessions/devices, or recover
  access.

Credential lifecycle transitions should be explicit core commands or runtime facades, not
application-owned sequences of lower-level calls. The likely transition families are:

- add a credential to the current subject;
- replace an existing credential instance;
- remove a credential instance;
- rotate a credential secret or verifier;
- reset a lost credential while authenticated;
- recover or replace a credential while unauthenticated;
- schedule destructive account or subject-auth-state deletion;
- cancel pending deletion;
- revoke all sessions/devices after sensitive credential changes;
- start, approve, deny, or expire an admin/support recovery intervention;
- enforce a long waiting period before destructive deletion or second-factor reset;
- emit durable notices for credential additions, removals, resets, admin interventions,
  pending deletions, and deletion cancellation.

Long waits are first-class auth state. They should not be implemented as "send an email
and hope the app remembers." A scheduled deletion or delayed second-factor reset needs a
durable pending-action record with subject, action kind, requested-at,
earliest-execute-at, expires-at, cancellation policy, required notices, and atomic
execution preconditions. Successful login or a stronger recovery proof may cancel some
pending actions; other actions may require explicit cancellation.

Admin/support recovery must also be modeled as credential lifecycle policy, not a
side-door mutation. It needs explicit authorization provenance, waiting periods where
configured, user-visible durable notices, audit events, and post-action session/device
revocation rules. The core does not need to know application staff roles, but the runtime
boundary must accept a Paranoid-shaped verified admin intervention rather than letting app
code directly mutate credential records.

The core should make factor collapse hard to miss by representing dependencies directly.
One possible model is a small dependency graph:

- each credential instance declares what can create, reset, replace, disable, or recover
  it;
- each proof used in a lifecycle transition references the credential instance or external
  authority that produced it;
- proof-stack policy rejects source-less or same-source multi-proof stacks when known
  distinct sources are required;
- lifecycle policy rejects proof stacks whose effective recovery authorities overlap when
  deeper independence is required;
- policies can intentionally allow non-independent proofs for lower-risk transitions, but
  the allowance must be explicit in the transition policy.

This does not mean the lower core should become an application identity system. It means
auth-owned credentials need enough metadata for Paranoid to answer security questions the
application cannot safely answer by convention:

- Does this proof bind a subject, or does it require a known subject?
- Which credential instance produced this proof?
- Can this credential reset the other credential in the same proof stack?
- Is this reset path authenticated, unauthenticated, delayed, admin-mediated, or
  recovery-code mediated?
- Does this mutation require subject-wide revocation after commit?
- Does this mutation require durable notification before or after the waiting period?
- Is there a pending action that should block, delay, or be cancelled by this proof?

The lower layers being built now should therefore preserve room for:

- credential-instance/source identifiers in satisfied proof records;
- method-owned credential lifecycle state and core-visible lifecycle metadata;
- pending-action records with delayed execution;
- durable effects tied to lifecycle transitions;
- proof-stack policy that can ask for independence, not only family/method membership;
- runtime facades that derive subject and target credential context from validated state;
- storage preconditions that prevent stale resets, stale admin approvals, stale deletion
  execution, and concurrent credential replacement races.

The current reducer already has some early vocabulary for this, such as
`ProofUse::RecoverOrReplaceCredential`, subject-wide auth-state revocation, method commit
work, durable effects, active-proof attempts, and satisfied-proof source provenance. That
is not enough. It is scaffolding for a credential lifecycle policy layer that still needs
explicit design and tests.

The first concrete credential metadata foothold is `CredentialInstanceMetadata`. It
represents app-owned credential instances only:

- message-signature verifiers;
- shared-secret OTP verifiers such as TOTP;
- origin-bound public-key credentials such as WebAuthn/passkeys;
- recovery-code credentials;
- trusted-device credentials.

Out-of-band identifiers and federated identity authorities remain distinct proof-source
kinds, not credential instances. That separation matters because email ownership and OIDC
authority can participate in recovery policy, but they must not be silently treated as the
same kind of app-owned credential as a TOTP secret or passkey credential.

Credential-instance metadata currently records subject id, credential-instance id,
credential kind, method label, and lifecycle state. Only `Active` credential instances may
produce new proofs. Pending, consumed, revoked, expired, superseded, scheduled, or
admin-suspended credentials are metadata the policy may inspect, not proof sources the
runtime may accept as fresh proof producers.

Recovery-authority metadata is modeled with effective `RecoveryAuthorityId`s. A recovery
authority id is not a proof-source id and not a credential id. It represents one effective
authority that can recover or mutate credentials. Multiple distinct proof sources can
share one recovery authority id when they depend on the same upstream control. For
example, an email OTP proof source and an OIDC provider proof source can be different raw
proof sources while both representing the same Google Workspace authority for lifecycle
policy.

Lifecycle authority evidence can currently come from:

- a satisfied proof source;
- a live authenticated session;
- a Paranoid-shaped admin/support intervention.

Each evidence source carries one or more effective recovery authority ids. Two evidence
sources are lifecycle-independent only when their effective recovery-authority id sets are
disjoint. This is stricter than proof-stack source distinctness. Distinct raw proof
sources are not enough when they collapse to the same upstream recovery authority.

Each target credential lifecycle action can declare which effective recovery authorities
can perform it and whether that authority is immediate or delayed. Immediate authorities
collapse factor independence for that target/action. Delayed authorities do not count as
immediate reset authority, which preserves the password-reset non-degradation model:
email-only reset can be allowed as a delayed pending action for stronger subjects without
pretending email is an immediate independent second factor.

Current lifecycle actions modeled for recovery-authority metadata are:

- create credential;
- reset credential;
- replace credential;
- remove credential;
- disable credential;
- regenerate credential set;
- recover subject access.

This metadata supports the first factor-collapse checks:

- a password resettable immediately by email is not independent from that email proof;
- a trusted-device credential can remain independent from email-only password reset when
  it has a separate recovery authority;
- a TOTP credential resettable by session alone is not independent from that session for
  the reset transition;
- recovery-code regeneration by email is not independent from that email proof;
- passkey removal by session alone is not independent from that session;
- OIDC and email proofs sharing the same upstream authority are not lifecycle-independent
  despite being distinct proof sources;
- immediate admin/support intervention is an explicit recovery authority, not an invisible
  side door.

The production Postgres core now has first-class reducer-owned storage for this metadata:

- credential-instance rows store subject id, credential-instance id, credential kind,
  method label, and lifecycle state;
- credential recovery-authority rows store target credential id, lifecycle action,
  effective recovery authority id, and whether the authority is immediate or delayed;
- lifecycle authority-source rows map verified proof sources, authenticated sessions, and
  admin/support interventions to effective recovery authority ids;
- pending credential-lifecycle action rows store subject id, target credential id,
  lifecycle action, requested-at, earliest-execute-at, expires-at, and closed-at.
- pending subject-lifecycle action rows store subject id, subject lifecycle action,
  requested-at, earliest-execute-at, expires-at, and closed-at.

The current concrete lifecycle decision boundary is intentionally narrow. Given a target
credential and already verified lifecycle evidence, the Postgres store can load the
credential metadata, recovery-authority graph, and authority-source bindings inside the
current transaction and evaluate a lifecycle action. The decision distinguishes:

- immediate authorization;
- delayed-action requirement because configured authority is delayed-only;
- delayed-action requirement because the only authorizing evidence would collapse factor
  independence;
- rejection because the target is inactive, absent, or not authorized by the graph.

The first concrete credential reset planning and execution transitions now consume this
boundary. Planning either:

- commits immediate reset authorization, optional subject auth-state revocation, audit,
  and a durable security notice; or
- creates one delayed pending reset action guarded by target-credential liveness and
  open-pending-action uniqueness, with audit and durable notice committed in the same
  transaction.

Execution accepts either an immediate lifecycle-authorized context or one matured pending
reset action. It requires method/plugin commit work for the target credential family and
method, locks the target credential, locks the pending action when one is being consumed,
applies method-owned verifier mutation work in the same atomic commit, closes the pending
action when applicable, records execution, optionally raises subject auth-state
revocation, and schedules an execution security notice.

The Postgres runtime now protects the planning and execution boundaries from
application-shaped shortcuts. The general web runtime rejects direct credential-reset
planning and execution commands. Authenticated reset planning derives the live session and
lifecycle authority inside the runtime, loads the target credential lifecycle decision in
the transaction, and generates any pending-action id internally. Unauthenticated recovery
planning derives lifecycle evidence from a validated `RecoverOrReplaceCredential`
active-proof attempt, verifies that the attempt subject matches the target credential,
generates any pending-action id internally, and closes that active-proof attempt in the
same commit as the reset plan. Authenticated reset execution derives the live session and
lifecycle authority inside the runtime, loads the target credential lifecycle decision in
the transaction, and asks the registered method plugin to build method-owned reset work
for the target credential. Matured pending reset execution loads the pending action and
target credential inside the transaction, verifies that the pending action is still
executable during commit, and asks the registered method plugin to build the method-owned
reset work. Applications do not pass `method_commit_work`, pending-action authority,
satisfied lifecycle authority facts, or preassembled reset planning/execution commands
through these facades.

This is still only the first credential-reset execution boundary. Public mounted reset
facades, concrete password/TOTP/recovery-code reset method implementations,
add/remove/replace credential scheduling, mounted deletion waits, subject-targeted
Postgres runtime facades, and admin/support intervention are not built. Future password
reset, TOTP reset, recovery-code regeneration, and pending-action commands should consume
this boundary instead of reimplementing factor-collapse checks.

Credential-reset pending-action cancellation now exists as a separate lifecycle
transition. The runtime derives the cancelling subject from a live authenticated session,
loads the pending action and target credential inside the transaction, verifies the
pending action belongs to that subject, and then asks the reducer to close only an open
and unexpired pending reset action for that exact target/action. Commit-time preconditions
lock the target credential and prove the pending action is still open, unexpired, and
target-matched before the close mutation, cancellation audit event, and cancellation
security notice commit.

Credential-reset pending-action expiry is deadline-derived, not a separate positive auth
decision. Once `now >= expires_at`, the pending reset cannot execute or be cancelled as a
user-visible cancellation. Expired rows may still have `closed_at IS NULL` until a
maintenance path touches them, but they are semantically expired immediately by time.
Storage preconditions that schedule a new pending reset quietly close expired open rows
for the same target/action before enforcing open-action uniqueness. That quiet cleanup
does not enqueue a cancellation notice or create a user-facing cancellation outcome.

The shared pending-action semantics are no longer reset-only. Credential-targeted delayed
actions have a common contract:

- `Reset`, `Replace`, `Remove`, and `Regenerate` can be credential-targeted pending
  actions.
- `Reset`, `Replace`, and `Regenerate` require method-owned credential mutation work at
  execution.
- `Remove` is primarily a core credential lifecycle-state mutation; method-owned cleanup
  can be layered on later, but proof production must already be blocked by core credential
  metadata.
- `Replace` supersedes the target credential on execution.
- `Remove` revokes or removes the target credential from proof production on execution.
- All credential-targeted pending actions share the same cancellation and expiry shape:
  explicit cancellation is only for open, unexpired actions and emits cancellation
  audit/notice; expiry is deadline-derived and quiet cleanup may close expired rows
  without producing a cancellation outcome or notice.
- Subject-wide auth-state revocation is not implicit for credential-targeted pending
  execution. Each concrete transition must choose and record its revocation policy.

The reducer now has concrete non-reset pending-action execution and cancellation commands
for credential-targeted `Replace`, `Remove`, and `Regenerate` actions. These commands are
still lower-core WIP commands, not mounted application APIs. The generic web runtime
rejects direct calls to them. Their current contracts are:

- replacement execution locks the pending action and target credential, requires
  method-owned work matching the target credential family/method, closes the pending
  action, records execution, marks the old target credential `Superseded`, optionally
  raises subject auth-state revocation, and commits a replacement notice;
- removal execution locks the pending action and target credential, forbids method-owned
  work in the current contract, closes the pending action, records execution, marks the
  target credential `Revoked`, optionally raises subject auth-state revocation, and
  commits a removal notice;
- regeneration execution locks the pending action and target credential, requires
  method-owned work matching the target credential family/method, closes the pending
  action, records execution, preserves the target credential lifecycle state, optionally
  raises subject auth-state revocation, and commits a regeneration notice;
- cancellation for these non-reset credential-targeted actions closes only open,
  unexpired, target-matched pending actions and commits the action-specific cancellation
  audit/notice.

Concrete Postgres runtime facades now execute matured credential-targeted replacement,
removal, and regeneration actions by loading the pending row and target credential inside
the transaction. Replacement and regeneration ask the registered target-credential method
plugin to construct method-owned mutation work from an opaque runtime input payload.
Removal is core-owned and rejects method work. The same runtime boundary provides
authenticated cancellation for open, unexpired non-reset credential-targeted actions.
Applications still do not pass pending action records, target credential metadata,
lifecycle authority facts, or method commit work.

Delayed subject/account deletion is deliberately not forced into the credential-targeted
pending-action row. It is a subject-targeted lifecycle action. Its pending action must
target subject auth state, not a fake credential id. Execution of subject deletion
requires subject-wide auth-state revocation semantics and app-facing deletion integration
once the mounted runtime exists. The lower core now has a dedicated subject pending-action
record, scheduling command, execution command, cancellation command, subject-specific
preconditions, subject-specific storage table contract, deletion audit events, and
deletion security notices. The Postgres runtime executes matured subject-auth-state
deletion actions by loading the pending subject action inside the transaction, and it
provides authenticated cancellation by deriving the cancelling subject from a live session
rather than caller-provided subject facts. The mounted runtime still needs to decide how
application-owned subject/account data is deleted or disabled around that core auth-state
mutation.

"Second-factor reset" is also not a separate credential kind and must not be inferred from
TOTP, WebAuthn, SMS, or any other plugin label. It is a lifecycle policy role over a
credential reset transition. The same `Reset` pending-action contract can represent a
password reset, TOTP reset, passkey reset, or other verifier reset; policy decides whether
the target credential is acting as a second factor and therefore which delay, proof,
notice, and revocation requirements apply.

## Fast-Fail Transition Matrix

This matrix is the design checklist for every auth transition. The goal is not merely to
use fast-fail where it falls out naturally. The goal is to actively search for safe
protocol shapes where impossible or abusive requests can be rejected before authoritative
storage work.

The `Current live shape` column is status, not proof. Some rows are fully implemented and
tested; some are model contracts; some are deliberately future method scopes. If a row
claims no database work before rejection, that claim needs executable operation-count or
load-boundary tests before it can be treated as pinned.

| Transition                                                           | Pre-state rejection gate                                                                                                                                                                      | Sealed or presented state                                                                                                                                                         | Authoritative work after gate                                                                                                             | Current live shape                                                                                                                                                                                                                                                                                                   |
| -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Safe read with fresh safe-read cache                                 | Encrypted session cookie deadline rejects expired cache without DB.                                                                                                                           | Session cookie carries session id, secret, hard session ceiling, and bounded safe-read deadline.                                                                                  | None for accepted safe reads; state-changing and sensitive requests still load state.                                                     | Modeled and covered by request-resolution/load-contract tests.                                                                                                                                                                                                                                                       |
| Session resolution after cache miss or unsafe request                | Cookie expiry ceilings reject impossible sessions before session lookup.                                                                                                                      | Session cookie carries id and secret; storage keeps MACs and version state.                                                                                                       | Load session, classify secret, check revocation, refresh window, step-up freshness, and subject-wide revocation.                          | Modeled in reducer, Postgres runtime, and request-resolution tests.                                                                                                                                                                                                                                                  |
| Trusted-device silent revival                                        | Trusted-device cookie expiry and silent-revival deadline reject impossible passive revival before DB.                                                                                         | Trusted-device cookie carries credential id, secret, hard credential ceiling, and silent-revival ceiling.                                                                         | Load credential, classify secret, check revocation, create session, rotate device credential.                                             | Modeled in reducer, Postgres runtime, and lifecycle tests.                                                                                                                                                                                                                                                           |
| Start step-up active-proof attempt                                   | Session cookie expiry rejects impossible step-up starts before DB.                                                                                                                            | Session cookie supplies the current subject/session context; caller supplies no subject id.                                                                                       | Load session and subject revocation, validate session secret, create subject-bound attempt and continuation credential.                   | Runtime has current-session start facades; generic and Postgres tests prove missing sessions do not write and valid starts derive subject.                                                                                                                                                                           |
| Start trusted-device active-revival proof attempt                    | Trusted-device cookie expiry rejects impossible active-revival starts before DB.                                                                                                              | Trusted-device cookie supplies the subject/device context; caller supplies no subject id.                                                                                         | Load device credential and subject revocation, validate device secret, create subject-bound attempt and continuation credential.          | Postgres lifecycle coverage starts active revival from the validated trusted-device cookie rather than a caller-supplied subject.                                                                                                                                                                                    |
| Trusted-device active revival                                        | Trusted-device cookie expiry and active-proof continuation cookie deadline/secret can reject impossible revival before DB.                                                                    | Trusted-device cookie supplies known subject/device context; active-proof continuation cookie supplies attempt id plus secret.                                                    | Validate device record and active-proof attempt, then issue a session and rotate device credential after proof-stack policy passes.       | Postgres runtime derives the attempt id from the continuation cookie and covers active revival through PgBouncer-backed tests.                                                                                                                                                                                       |
| Start unauthenticated active-proof attempt and issue first challenge | Runtime-owned weak gate can reject write-amplifying challenge starts before attempt/challenge writes.                                                                                         | Challenge issue request names intended proof use and method; no app-supplied proof verification facts are accepted.                                                               | Commit attempt start and challenge issue atomically, including continuation credential, method work, and durable delivery command.        | Postgres runtime has fused start-and-issue paths with preflight verification and continuation-cookie response materialization.                                                                                                                                                                                       |
| Issue out-of-band challenge on an existing attempt                   | Active-proof continuation cookie deadline/secret rejects impossible challenge issue before attempt load; no caller may preassemble the fast-fail cookie.                                      | Continuation cookie carries attempt id plus secret; encrypted challenge cookie carries challenge id, proof summary, nonce, and MAC.                                               | Load attempt and subject revocation, enforce dedupe/open-attempt preconditions, store challenge, enqueue delivery.                        | Runtime derives the attempt id from the continuation cookie; Postgres method registry supplies generated response-secret material and method work.                                                                                                                                                                   |
| Resend out-of-band challenge                                         | Encrypted challenge cookie must validate as an unexpired out-of-band ceremony before any DB load.                                                                                             | Same challenge cookie identifies the existing attempt and challenge; caller supplies only a fresh delivery idempotency key.                                                       | Load attempt/challenge, enforce open challenge and resend budget, append delivery work.                                                   | Postgres runtime validates cookie before loading state and obtains method work from the registry.                                                                                                                                                                                                                    |
| Complete out-of-band challenge                                       | Wrong submitted response rejects by MAC from the encrypted challenge cookie before any DB load.                                                                                               | Encrypted cookie carries response MAC and challenge context; submitted response is secret material.                                                                               | Load attempt/challenge and subject revocation, resolve subject through method state, close challenge, consume method state, record proof. | Postgres runtime verifies MAC first, then resolves subject and method work through the registry inside the post-gate transaction.                                                                                                                                                                                    |
| Issue message-signature challenge                                    | Runtime-issued nonce and method-sealed verifier/context must be generated during challenge issue; any necessary lookup belongs here, not on completion.                                       | Encrypted challenge cookie carries nonce and method state such as canonical-message hash or sealed verifier material.                                                             | Store any method challenge state only through method commit work if needed.                                                               | Runtime supports active-method challenge issue through the method registry. The first-party password-derived signature plugin loads the verifier during issue and seals canonical message/verifier state.                                                                                                            |
| Complete message-signature challenge                                 | Signature over the bound challenge should reject before DB when verifier material was sealed at issue time; online-guessable methods must bind the weak gate to the submitted proof material. | Encrypted cookie carries proof summary, nonce, deadline, and method challenge state; weak-gate verification receives a digest of the exact challenge state plus response payload. | After signature success, load attempt/challenge and authoritative verifier/version state before accepting proof.                          | First-party password-derived signature tests prove wrong signatures reject before DB, successful signatures recheck locked authoritative verifier/version state, and a weak gate solved for one signature cannot be reused for another signature.                                                                    |
| Issue origin-bound public-key challenge                              | Runtime-issued challenge, origin/RP context, and credential lookup context are sealed before completion.                                                                                      | Encrypted cookie carries nonce, origin/RP binding, credential/challenge state, and deadline.                                                                                      | Authoritative credential state must still validate credential status, subject mapping, and replay/sign-count rules.                       | Contract and test-plugin paths exist; mature WebAuthn/passkey plugin is not built.                                                                                                                                                                                                                                   |
| Complete origin-bound public-key challenge                           | Assertion structure, origin/RP binding, and signed challenge can reject before DB when sealed challenge state is sufficient.                                                                  | Encrypted cookie carries proof identity and method challenge state.                                                                                                               | Load attempt/challenge and authoritative credential state before accepting proof or mutating counters.                                    | Test-plugin paths cover the family shape; concrete WebAuthn/passkey implementation is not built.                                                                                                                                                                                                                     |
| Issue federated-identity challenge                                   | Runtime-generated state/nonce/redirect binding rejects mismatched callbacks before subject mapping.                                                                                           | Encrypted state cookie carries issuer, audience/client, redirect binding, nonce, state, deadline, and provider context.                                                           | Authoritative issuer config, external subject mapping, and account-link policy still gate success.                                        | Contract and test-plugin paths exist; concrete OIDC/SAML implementation is not built.                                                                                                                                                                                                                                |
| Complete federated-identity assertion                                | Invalid state, nonce, issuer, audience, or assertion signature can reject before local account mapping.                                                                                       | Encrypted state cookie binds the callback to the initiated ceremony.                                                                                                              | Load attempt/challenge and authoritative mapping/linking state before accepting proof.                                                    | Test-plugin paths cover the family shape; concrete OIDC/SAML implementation is not built.                                                                                                                                                                                                                            |
| Direct known-subject TOTP                                            | Weak gate rejects before DB; direct code verification cannot reject wrong TOTP before fetching the subject verifier.                                                                          | Existing session, trusted device, or prior proof supplies the subject-bound attempt.                                                                                              | Load attempt and subject verifier, verify code, record success or weak failure.                                                           | Postgres tests assert invalid weak gates perform no DB work; wrong codes with valid gates perform the authoritative verifier lookup and spend the ceremony weak-failure budget.                                                                                                                                      |
| Challenge-bound TOTP                                                 | Encrypted challenge cookie plus Bloom filter can reject definite non-matches before DB; weak gate must also pass before state load.                                                           | Encrypted cookie carries TOTP challenge context and Bloom bitset for the acceptable human window.                                                                                 | Possible Bloom hits still load attempt, subject revocation, challenge row, and locked authoritative verifier/version state.               | First-party Postgres runtime lane is live. Tests assert definite Bloom misses perform no DB work, valid possible hits perform authoritative lookup and record credential-instance source, stale verifier-version possible hits record failure authoritatively, and late-window accepted codes do not false-negative. |
| Recovery code                                                        | Canonical base58 parsing plus AEAD decrypt/tag verification rejects malformed or guessed sealed codes before DB; known-subject flows also reject subject mismatch before DB.                  | Opaque sealed recovery code carries subject id plus random token; no public prefix or lookup id is exposed.                                                                       | MAC the decrypted random token, lock the unused code row for that subject, and consume atomically with proof success.                     | Postgres tests assert malformed, guessed, and wrong-subject sealed tokens perform no DB work; plausible sealed-but-unused tokens perform authoritative lookup, reject, and consume nothing.                                                                                                                          |
| Add credential                                                       | Existing session, step-up freshness, active-proof continuation, and challenge cookies reject impossible add requests before target credential work.                                           | Current session plus active proof stack identify subject and proposed credential context.                                                                                         | Evaluate lifecycle policy, verify proof independence when required, create pending or active credential, enqueue notices.                 | Not built; lower core must preserve credential-instance ids and lifecycle metadata.                                                                                                                                                                                                                                  |
| Replace or reset credential                                          | Existing session/trusted-device/proof cookies and weak gates reject impossible reset ceremonies before target credential lookup where possible.                                               | Active proof stack plus target credential context.                                                                                                                                | Evaluate dependency graph, reject collapsed factors, enforce wait/admin/recovery-code rules, replace credential atomically.               | Credential reset planning and execution boundary exist; concrete mounted reset flows and first-party method reset implementations are not built.                                                                                                                                                                     |
| Remove credential                                                    | Session and step-up material reject impossible remove requests before loading target credential when no live authority exists.                                                                | Current subject context plus target credential instance.                                                                                                                          | Enforce last-credential and independence policy, mark removed/revoked, revoke sessions/devices when policy requires it.                   | Not built.                                                                                                                                                                                                                                                                                                           |
| Schedule delayed deletion or reset                                   | Session/proof cookies and weak gates reject impossible schedule requests before writes.                                                                                                       | Subject context, requested action kind, target credential or subject, cancellation rules, and notice requirements.                                                                | Create durable pending-action record, enqueue notices, define earliest execution time and expiration.                                     | Delayed credential-reset scheduling exists; lower-core subject-auth-state deletion scheduling exists; concrete replacement/removal/regeneration scheduling and mounted deletion scheduling remain open.                                                                                                              |
| Execute pending deletion or reset                                    | Pending-action id plus deadline can reject too-early or expired execution before broader state work.                                                                                          | Pending-action record identifies subject, action, target, earliest execution time, expiration, and required prior notices.                                                        | Lock pending action and target state, enforce stale-action preconditions, execute mutation, revoke sessions/devices, audit.               | Pending credential-reset execution exists; non-reset credential-targeted execution exists; Postgres subject-auth-state deletion execution exists; mounted application deletion integration remains open.                                                                                                             |
| Cancel pending deletion or reset                                     | Session/proof cookies can reject impossible cancellation before pending-action or target mutation work.                                                                                       | Subject context plus pending-action id.                                                                                                                                           | Verify cancellation policy, close unexpired pending action, enqueue cancellation notice.                                                  | Built for authenticated credential-reset and non-reset credential-targeted pending actions; Postgres subject-auth-state deletion cancellation exists; mounted deletion integration remains open.                                                                                                                     |
| Admin/support recovery intervention                                  | Runtime must reject unverified app claims; only a Paranoid-shaped verified intervention can reach stateful recovery work.                                                                     | Verified admin/support authority, subject/credential target, configured wait/notice policy, and active proof if required.                                                         | Audit intervention, create or execute pending action, enforce notices and revocation policy.                                              | Not built; must not become an app-owned side-door mutation.                                                                                                                                                                                                                                                          |
| Complete full authentication                                         | Active-proof continuation cookie deadline and secret can reject impossible or stolen-id completions before loading the attempt.                                                               | Active-proof continuation cookie carries attempt id plus secret; attempt records carry satisfied proof summaries and subject binding.                                             | Load attempt, validate proof-stack policy, check subject revocation, create session and optional trusted device.                          | Postgres runtime derives the attempt id from the continuation cookie and covers full-authentication completion through PgBouncer-backed tests.                                                                                                                                                                       |
| Complete step-up                                                     | Fresh session cookie and active-proof continuation cookie deadlines can reject impossible completion before loading old session state.                                                        | Session cookie plus active-proof continuation cookie.                                                                                                                             | Load session and attempt, validate subject match and proof-stack policy, refresh step-up freshness.                                       | Postgres runtime derives the attempt id from the continuation cookie and covers step-up completion through PgBouncer-backed tests.                                                                                                                                                                                   |
| Logout and targeted revocation                                       | Missing or expired cookies can avoid unnecessary state work when no live credential can be affected.                                                                                          | Presented session or trusted-device cookie identifies target context.                                                                                                             | Load and lock target credential when needed, mark revoked, clear cookies.                                                                 | Modeled in reducer and Postgres runtime tests.                                                                                                                                                                                                                                                                       |
| Subject-wide revocation                                              | Caller must already have an authenticated subject context; no stateless material alone may revoke a subject.                                                                                  | Authenticated session context identifies the subject.                                                                                                                             | Commit subject auth-state revocation and ensure older sessions/devices cannot succeed afterward.                                          | Modeled in reducer and Postgres runtime tests.                                                                                                                                                                                                                                                                       |

## Fast-Fail Audit Status

This audit records the current live status of the matrix above. "Live and covered" means
the current code and tests exercise the ordering claim. It does not mean every final
operation-count test, first-party plugin, public API, or lifecycle policy is finished.

| Transition                                                           | Audit result                                                                                                                                                                    | Evidence or remaining work                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Safe read with fresh safe-read cache                                 | Live and covered at request-resolution/load-contract level.                                                                                                                     | Add final mounted-runtime operation-count coverage once the public request path exists.                                                                                                                                                                                                                                                                                    |
| Session resolution after cache miss or unsafe request                | Live and covered at reducer, load-contract, and Postgres runtime level.                                                                                                         | Add final mounted-runtime tests proving expired/impossible cookies do not perform storage work.                                                                                                                                                                                                                                                                            |
| Trusted-device silent revival                                        | Live and covered at reducer and Postgres runtime level.                                                                                                                         | Add final operation-count coverage for impossible passive revival cookies.                                                                                                                                                                                                                                                                                                 |
| Start step-up active-proof attempt                                   | Live and covered.                                                                                                                                                               | Runtime derives subject from validated session state; tests cover missing-session starts without writes.                                                                                                                                                                                                                                                                   |
| Start trusted-device active-revival proof attempt                    | Live and covered.                                                                                                                                                               | Runtime derives subject/device from the trusted-device cookie and authoritative device state.                                                                                                                                                                                                                                                                              |
| Trusted-device active revival                                        | Live and covered.                                                                                                                                                               | Postgres tests cover revival through continuation cookies and trusted-device rotation.                                                                                                                                                                                                                                                                                     |
| Start unauthenticated active-proof attempt and issue first challenge | Live and covered for runtime-owned preflight and fused atomic start/issue.                                                                                                      | Final anti-abuse policy still needs concrete progressive-friction and delivery-cooldown design.                                                                                                                                                                                                                                                                            |
| Issue out-of-band challenge on an existing attempt                   | Live and covered for continuation-cookie derivation and runtime-owned challenge-cookie construction.                                                                            | Final operation-count tests should prove invalid continuation material avoids state work.                                                                                                                                                                                                                                                                                  |
| Resend out-of-band challenge                                         | Live and covered for missing, malformed, wrong-family, and expired challenge-cookie rejection before storage work.                                                              | Postgres runtime tests assert the database operation observer is empty for these resend rejection shapes.                                                                                                                                                                                                                                                                  |
| Complete out-of-band challenge                                       | Live and covered for wrong submitted response rejection before storage work.                                                                                                    | Generic runtime tests assert bad response MAC causes zero load/commit; Postgres email OTP tests assert wrong OTP leaves the database operation observer empty.                                                                                                                                                                                                             |
| Issue message-signature challenge                                    | First-party password-derived signature issue path is live and covered.                                                                                                          | Password-derived challenge issue loads salt, KDF params, public verifier, credential id, subject id, and verifier version when a verifier exists, then seals canonical message/verifier state in the encrypted challenge cookie. SSH, wallet, and similar methods remain future plugin scopes.                                                                             |
| Complete message-signature challenge                                 | First-party password-derived signature completion is live and covered for the core fast-fail/recheck claim.                                                                     | Postgres runtime tests assert wrong password-derived signatures leave the database operation observer empty, accepted signatures perform a locked verifier/version recheck, stale verifier rotation rejects after pre-state signature success, and native Hashcash material bound to one submitted signature rejects before DB when replayed with another signature.       |
| Issue origin-bound public-key challenge                              | Contract shape exists; concrete WebAuthn/passkey plugin is not built.                                                                                                           | Mature crate selection and origin/RP challenge-state design are still open implementation work.                                                                                                                                                                                                                                                                            |
| Complete origin-bound public-key challenge                           | Contract shape exists; concrete WebAuthn/passkey plugin is not built.                                                                                                           | Tests must prove origin/RP/challenge failures reject before local state and that authoritative credential state still gates success.                                                                                                                                                                                                                                       |
| Issue federated-identity challenge                                   | Contract shape exists; concrete OIDC/SAML plugin is not built.                                                                                                                  | Mature crate selection and state/nonce/redirect/issuer/audience binding design are still open implementation work.                                                                                                                                                                                                                                                         |
| Complete federated-identity assertion                                | Contract shape exists; concrete OIDC/SAML plugin is not built.                                                                                                                  | Tests must prove invalid state, nonce, issuer, audience, and assertion signature fail before local mapping, while mapping/linking remains authoritative.                                                                                                                                                                                                                   |
| Direct known-subject TOTP                                            | Runtime lane is live for weak-gate-before-load, authoritative wrong-code handling, and credential-instance proof provenance.                                                    | Postgres tests assert invalid weak gate leaves the database operation observer empty, wrong code with native Hashcash evidence bound to the submitted TOTP response performs the verifier lookup and records a weak failure, and accepted proof records the TOTP credential-instance source. The real verifier uses `totp-rs` through a Paranoid-owned wrapper.            |
| Challenge-bound TOTP                                                 | First-party Postgres runtime/plugin lane is implemented and covered for the core fast-fail/recheck claim.                                                                       | Tests cover primitive context binding, key rotation, shape bounds, definite non-match behavior, native Hashcash binding to the submitted TOTP response, runtime definite-miss no-DB behavior, possible-hit authoritative verifier/version recheck, cookie budget, and late-window no-false-negative behavior. Broader mounted-runtime operation counts remain future work. |
| Recovery code                                                        | Runtime/plugin skeleton exists for atomic consume-on-success, sealed-token pre-state rejection, and plausible-token authoritative misses that consume nothing.                  | Implement the lifecycle/runtime path that generates and stores new user-visible recovery codes.                                                                                                                                                                                                                                                                            |
| Add credential                                                       | Not built.                                                                                                                                                                      | Requires credential-instance metadata, recovery-authority graph, lifecycle policy, durable notices, and mounted API design.                                                                                                                                                                                                                                                |
| Replace or reset credential                                          | Partially built for credential reset planning and execution boundary.                                                                                                           | Concrete mounted reset flows, first-party method reset implementations, admin/support policy, cancellation, and broader replacement flows remain.                                                                                                                                                                                                                          |
| Remove credential                                                    | Not built.                                                                                                                                                                      | Requires last-credential and independence policy plus post-mutation revocation rules.                                                                                                                                                                                                                                                                                      |
| Schedule delayed deletion or reset                                   | Partially built for credential-reset pending action scheduling, lower-core subject-auth-state deletion scheduling, and shared pending-action semantics.                         | Mounted deletion scheduling, second-factor reset, delayed replacement scheduling, cancellation policy, and broader notice policy remain.                                                                                                                                                                                                                                   |
| Execute pending deletion or reset                                    | Built for pending credential-reset execution, non-reset credential-targeted execution, and Postgres subject-auth-state deletion execution.                                      | Mounted application deletion integration and final mounted-runtime stale-action tests remain.                                                                                                                                                                                                                                                                              |
| Cancel pending deletion or reset                                     | Built for authenticated credential-reset cancellation, reset expiry cleanup, non-reset credential-targeted cancellation, and Postgres subject-auth-state deletion cancellation. | Mounted deletion integration and final mounted-runtime cancellation tests remain.                                                                                                                                                                                                                                                                                          |
| Admin/support recovery intervention                                  | Not built.                                                                                                                                                                      | Requires Paranoid-shaped verified intervention, wait/notice policy, audit, and revocation rules.                                                                                                                                                                                                                                                                           |
| Complete full authentication                                         | Live and covered.                                                                                                                                                               | Postgres runtime derives attempt id from continuation cookie and creates session/trusted-device state only after authoritative proof-stack validation.                                                                                                                                                                                                                     |
| Complete step-up                                                     | Live and covered.                                                                                                                                                               | Postgres runtime derives attempt id from continuation cookie and validates session/attempt subject match before updating freshness.                                                                                                                                                                                                                                        |
| Logout and targeted revocation                                       | Live and covered.                                                                                                                                                               | Postgres runtime tests cover cookie clearing and stale DB state rejection after revocation.                                                                                                                                                                                                                                                                                |
| Subject-wide revocation                                              | Live and covered.                                                                                                                                                               | Postgres runtime tests cover sessions and trusted devices created before revocation being rejected afterward.                                                                                                                                                                                                                                                              |

## Fast-Fail Shapes

### Out-Of-Band Codes

Out-of-band challenge responses use encrypted challenge cookies containing a fast-fail
verifier. A wrong submitted code must be rejected before loading challenge, attempt,
subject, or method state.

The method plugin should generate response-secret material for issuance and hand it to the
runtime together with method commit work. Applications should not manufacture OTP/code
secrets. The verifier must be bound to stable challenge context so code material cannot be
reused across ceremonies. A successful verifier check still proceeds to DB-backed
validation and method commit work.

Resend must first validate the encrypted challenge cookie. Resend should continue the same
active ceremony; it must not create a new proof shape as a side effect of asking for
delivery again.

### Message Signatures

Message signatures prove control over a signing key by signing a runtime-issued,
context-bound challenge.

Password-derived signing belongs under this family. The server stores a public verifier,
not a password hash. The client derives a signing key from the password and signs a
challenge.

The important corrected model is:

1. Challenge issuance may do the necessary authoritative lookup for salt, verifier, method
   version, and subject context.
2. The runtime seals the verifier or enough verifier material into the encrypted challenge
   cookie.
3. Completion decrypts the cookie, verifies deadline and context, verifies the weak-proof
   gate if the method is online-guessable, binds that gate to the exact sealed challenge
   state plus submitted response payload, and checks the submitted signature against the
   sealed verifier before any completion-time DB hit.
4. Wrong password-derived signatures reject before DB.
5. Signature success still requires authoritative state before granting access or mutating
   durable auth state.

The branch in the raw notes where `/login/verify` reads the current public key before
signature verification is only one older sketch. It is not the best current design if the
challenge-issue step already loaded and sealed the verifier.

First-party message-signature methods should therefore treat completion-time
DB-before-signature verification as a regression unless a specific method cannot safely
seal enough verifier context at issue time. If such a method exists, the method must say
why in its method contract and must not inherit the stronger password-derived fast-fail
claim.

For password-derived signatures, the weak-proof gate is bound to the exact active-method
challenge material and response payload. A solved gate must not be reusable across
password guesses.

### Shared-Secret OTP

TOTP and similar configured secrets are known-subject proofs. Direct TOTP cannot identify
a subject from nothing. It must have subject context from an existing session, trusted
device, or prior active proof.

The alpha direct TOTP verifier row carries a stable TOTP credential-instance id.
Successful TOTP verification records that id as a `CredentialInstance` proof source, not
merely a source-less "TOTP succeeded" fact. The encrypted TOTP secret is
associated-data-bound to both subject id and credential-instance id, so verifier
ciphertext cannot be silently moved to a different credential instance and still decrypt
as valid method state.

The direct known-subject lane requires a weak-proof gate before DB work. Invalid gate
evidence rejects before storage work. Once the weak gate is valid, a wrong TOTP code
cannot be rejected statelessly in the direct lane because the subject verifier is
authoritative state. That path must load the verifier, reject on mismatch, and spend only
the active ceremony's weak-failure budget. It must not lock out the subject or identifier.
That is the conventional path, but it is not the only Paranoid-shaped path.

The alpha direct TOTP implementation uses `totp-rs` through a Paranoid-owned wrapper.
Paranoid does not expose the dependency as the auth method API and does not let the crate
own credential lifecycle. Paranoid still owns encrypted TOTP secret storage,
associated-data binding, weak-gate sequencing, authoritative verifier lookup, proof-source
provenance, and lifecycle/recovery policy. The wrapper uses the mature crate only for
RFC-compatible token generation over SHA-1, SHA-256, and SHA-512, with Paranoid-owned
input-shape checks, time-window handling, and RFC 6238 vector coverage.

The raw notes also contain a stronger challenge-bound TOTP fast-fail idea:

1. After another proof fixes the subject, issue a short-lived encrypted challenge cookie.
2. The cookie contains a Bloom filter of all TOTP codes acceptable during the human
   challenge window.
3. The submitted TOTP response and weak-proof gate are bound to the challenge context.
4. Definite Bloom misses reject before DB.
5. Possible Bloom hits continue to authoritative TOTP verification and replay handling.

This must use a Bloom filter, not an exact MAC list. A normal 10 to 15 minute human
challenge window may include enough possible TOTP values that exact MAC entries spend too
much of the shared browser cookie budget. False positives are acceptable because they only
permit DB-backed verification. False negatives are not acceptable.

The current first-party Postgres TOTP lane implements this shape for subject-bound active
proof attempts. Challenge issue locks and seals the current verifier version into the
encrypted challenge state. Completion verifies the weak gate and Bloom definite-miss check
before storage work, then possible hits re-load the authoritative verifier/version before
recording success or failure.

### Recovery Codes

Recovery codes are high-entropy one-time proofs. Success requires method-owned commit work
that atomically consumes the code. Failure must not consume anything.

The alpha public shape is an opaque sealed token:

```text
recovery_code = base58(encrypt({ subject_id, random_token }))
```

The decrypted subject id is a candidate or consistency check, not stateless authentication
success. Recovery-code proof semantics still require authoritative one-time lookup and
consume before the proof can contribute to full authentication, step-up, trusted-device
revival, or recovery. In a flow that already has a known subject, subject mismatch rejects
before DB. In a recovery flow that starts from the token, the decrypted subject can route
the authoritative consume, but it must not by itself bind a successful proof.

The encrypted payload is intentionally minimal. It carries only the subject id and the
random token needed for authoritative one-time lookup. It does not expose a public prefix,
lookup id, timestamp, expiry, or other routing fields unless a concrete lifecycle policy
later proves one is needed.

Submitted recovery codes fast-fail before DB when they are not canonical base58, do not
decode to a valid encrypted payload, fail AEAD/tag verification, or, in a known-subject
flow, decrypt to a different subject. On decrypt success, the database is still
authoritative: the runtime MACs the random token in a subject-bound context, locks the
unused recovery-code row for that subject, verifies it is unused, and consumes it
atomically with proof success.

This is fast-fail for code-spray traffic, not stateless success. Random guesses should
usually die at parse/decrypt/tag verification. Plausible sealed tokens continue to
authoritative one-time lookup. If that lookup finds no unused matching code, the attempt
records proof failure but consumes no recovery code and does not spend an online-guessing
weak-failure budget, because recovery codes are high-entropy one-time secrets rather than
low-entropy online-guessable codes.

### Origin-Bound Public Keys

WebAuthn and passkeys are not generic message signatures. Origin, relying-party id,
challenge, client-data hash, credential id, authenticator flags, and sign-count semantics
are intrinsic to the family.

Concrete implementations should use mature protocol crates. The runtime still owns
challenge construction, encrypted cookie state, completion sequencing, and authoritative
subject/credential mutation.

### Federated Identity Assertions

OIDC and SAML-style methods are app-accepted assertions from another identity authority.
They are not app-owned factors in the same way as password-derived signing, TOTP, email
OTP, or trusted devices.

Concrete implementations should use mature protocol crates. Encrypted challenge state must
bind issuer, audience, redirect target, nonce, state, and PKCE-like data where applicable.
Assertion validity can be checked before subject mapping, but account linking and session
issuance remain authoritative state work.

## Weak Gates And Attempt Budgets

Online-guessable proofs need a runtime-owned weak gate before state loading. The old notes
often call this proof-of-work, but the core concept is broader: a pre-state-load cost,
human, or risk gate whose verified evidence is minted by the runtime, not supplied by the
caller as a naked fact.

Weak gates are not auth factors. They do not identify a subject, prove possession of a
credential, satisfy step-up, or contribute to proof-stack independence. They only decide
whether an online-guessable or write-amplifying request is allowed to proceed to the next
authoritative boundary.

The architecture has three first-class weak-gate families:

- Native proof of work: a Paranoid-owned Hashcash-style gate. The backend verifier and
  protocol format are first-party auth-core machinery. Browser/WASM solving remains part
  of the later client package.
- Human challenge: an adapter-backed gate such as Turnstile, reCAPTCHA, or a self-hosted
  CAPTCHA. Provider verification may perform external I/O, but it must happen before auth
  storage work and must not return subject or proof facts.
- Risk decision: an adapter-backed application or infrastructure decision. The adapter may
  use request context, but the runtime only accepts a gate pass/fail outcome and a
  Paranoid-owned gate summary. It must not let the application declare that an auth proof
  succeeded.

All weak-gate passes are runtime-owned evidence. Applications and method plugins submit
opaque gate response material. The runtime verifies that material through the configured
gate verifier and only then creates `VerifiedWeakProofGateBeforeStateLoad`-style evidence.
Reducer commands that require a weak gate should accept only that evidence shape, not a
caller-provided boolean or a plugin-declared success.

Proof-of-work evidence must be bound to the ceremony it protects. A solved gate must not
be reusable across password guesses, TOTP guesses, methods, proof uses, or challenge
instances. The binding context should include at least:

- the weak-gate method label and parameters;
- proof use;
- proof family and method label;
- runtime-issued gate nonce or challenge id;
- active-proof attempt id or challenge id when one already exists;
- method challenge context when the proof is challenge-bound;
- the submitted strong-proof payload or its canonical digest when the online attack would
  otherwise allow many guesses per solved gate.

For password-derived message signatures, the active-method completion path binds native
Hashcash evidence to a runtime-derived digest over the exact encrypted challenge state and
submitted response payload. For direct known-subject TOTP, the binding includes the
active-proof continuation credential, proof use, subject context, method declaration, and
submitted TOTP response. For challenge-bound TOTP, the binding includes the encrypted
challenge/Bloom context and the submitted TOTP response. For first unauthenticated
challenge issue, where no attempt exists yet, the preflight resource binds the requested
proof use and method so one solved gate cannot fan out into many method starts.

There must be no account-level lockouts. Account lockout is an attacker-controlled denial
of service primitive: if an attacker can name a subject or identifier and make the
legitimate user unable to authenticate, the auth system has handed availability to the
attacker.

Paranoid-owned anti-abuse policy should instead use ceremony-scoped controls:

- reject malformed, expired, impossible, or stateless-fast-fail-negative requests before
  authoritative state;
- require weak gates before write-amplifying unauthenticated challenge starts and
  online-guessable proof checks;
- count weak failures against the in-flight active-proof attempt, not the account;
- close or invalidate the current attempt when its weak budget is exhausted;
- require a new ceremony, stronger gate, or longer proof-of-work after repeated cheap
  failures without locking the account or identifier;
- limit or dedupe expensive side effects such as email, SMS, webhook, or push delivery;
- preserve legitimate user recovery paths even while an attack is ongoing.

Weak-gate failures before state loading should not create write amplification. A rejected
gate should be cheap to verify and should not require updating an account, identifier, or
attempt row. Stateful budgets are acceptable only after the request has presented enough
Paranoid-owned continuation material to deserve stateful work, such as a valid active
proof continuation cookie or challenge cookie.

Challenge issuance is the main unauthenticated write-amplification risk. Fused
attempt-start plus challenge-issue paths must require cheap preflight evidence before
creating attempt/challenge rows or durable delivery commands. Existing-attempt challenge
issue and resend paths must first validate the continuation or challenge cookie before
loading state.

Side-effect rate limiting is different from account lockout. Out-of-band delivery must
have durable dedupe and resend/cooldown rules so attackers cannot cheaply harass an
identifier or drain delivery budget. Those rules should bound sends and ceremonies without
making the named subject permanently or globally unable to log in.

Weak gates are configurable method/policy components. Paranoid provides a native
Hashcash-style proof-of-work backend verifier because it is app-owned, providerless, and
fits the fast-fail philosophy. Paranoid should also support human/risk gates through clear
runtime-owned integrations: Cloudflare Turnstile, Google reCAPTCHA, self-hosted CAPTCHA,
or an application risk engine can be adapters that verify provider evidence and mint a
Paranoid-owned `VerifiedWeakProofGateBeforeStateLoad`-style fact. Applications choose the
gate policy in config; they should not hand the core a naked "captcha passed" boolean.

The first public mounted API should make weak-gate policy explicit but hard to misuse:
methods declare whether they are online-guessable, transition policy chooses the required
gate family/method for that proof use, and the runtime constructs any gate challenge,
verifies responses, and records the gate summary on accepted failures or completions.
Applications may configure gates and adapter callbacks. They may not skip required gates,
share a solved gate across ceremonies, or decide that an online-guessable proof may be
checked without the configured gate.

Infrastructure rate limiting remains useful defense in depth. Operators should normally
rate-limit auth endpoints at a load balancer, reverse proxy, CDN, DNS edge, or similar
layer to absorb volumetric floods before application code runs. That infrastructure limit
is not the auth model's correctness mechanism: Paranoid must still be safe and
availability-preserving without Redis, without account lockouts, and without trusting
applications to implement auth-specific abuse controls.

## Durable Effects

External effects such as out-of-band delivery, security notifications, and method-owned
delivery commands must be durable effect records committed atomically with the auth state
transition. Delivery happens only from committed work.

Do not call arbitrary external effects after a DB commit as the only delivery guarantee;
that leaves a crash window. Do not perform external delivery before commit; that can leak
effects from failed transitions.

## Postgres Auth Bootstrap

Auth is a consumer of Paranoid's lower-level DB foundation, not a peer table family inside
the low-level KV/Fleet/Queue bootstrap. The intended production sequence is:

1. Run Paranoid DB foundation bootstrap for the dedicated schema, schema ledger, KV,
   Fleet, and Queue.
2. Run Auth bootstrap as a second-stage Paranoid subsystem over that foundation.

Auth bootstrap should use the same philosophy as the DB foundation bootstrap:

- one Paranoid-owned dedicated schema by default;
- schema-local derived table names;
- shared schema-ledger style version recording and validation;
- loud validation of adopted existing tables;
- transaction-pooler-safe SQL;
- byte-stable table semantics;
- no application-managed auth table choreography.

Auth should not use the advisory-lock bootstrap exception. By the time auth bootstrap
runs, the lower-level Paranoid DB foundation should already exist, so auth should use the
normal row-based coordination, migration, and ledger mechanisms available from that
foundation.

The current WIP Postgres auth config enforces this at the table-name layer:

- `PostgresAuthStoreConfig::default()` derives from `db::BootstrapConfig::default()`;
- `PostgresAuthStoreConfig::for_db_bootstrap_config(...)` uses the DB foundation schema
  and shared schema ledger table;
- auth core tables are schema-local names such as `auth_sessions`, not globally prefixed
  names such as `__paranoid_auth_sessions`;
- first-party method configs derive schema-local method table names such as
  `auth_email_otp_challenges`, `auth_totp_verifiers`, `auth_recovery_code_codes`, and
  `auth_password_signature_verifiers`.

The current private WIP auth bootstrap facade runs after DB foundation bootstrap,
constructs the core store and first-party method plugins from the same DB bootstrap
config, and migrates or validates auth-owned tables without application-managed table
choreography. It is intentionally one-shot when materializing the runtime because auth
credential keysets are moved into the store rather than cloned.

The public mounted auth configuration is still open. That later facade should wrap the
private bootstrap shape with route, cookie, CSRF, durable-effect, method-policy, and
application-hook configuration.

## Audit

All security-significant transitions need immutable audit coverage. At minimum, the design
must account for:

- full authentication;
- step-up;
- challenge issue, resend, completion, failure, replay, and budget exhaustion;
- session creation, refresh, rotation, revocation, and expiry;
- trusted-device creation, silent revival, active revival, rotation, revocation, expiry,
  and replay/tripwire;
- subject-wide revocation;
- credential lifecycle and recovery policy;
- scheduled deletion or delayed credential reset;
- admin/support recovery intervention;
- recovery-code consumption;
- security-significant durable effect enqueueing or idempotency collisions.

Audit should not become noisy request telemetry. Safe-read cache hits are not lifecycle
events by themselves.

## Privacy And Boundaries

Public identifier flows must be indistinguishable from outside observers. User-facing
responses should not reveal whether an email, account, method, or identifier exists.

Auth core should not know application identity shape such as organizations, accounts as
emails, resource ownership, or route authorization. It should operate on subject IDs and
proof semantics. Applications decide authorization.

User-agent strings may be stored for display. IP addresses are infrastructure guardrails,
not auth-core security identity signals.

## Current Implementation Status

The auth code is WIP private implementation behind the `__auth_wip` feature. It is not
ready as public API.

The reducer model currently includes:

- request resolution;
- bounded safe-read cache;
- authoritative session validation and refresh;
- trusted-device silent revival;
- trusted-device active-proof revival;
- full authentication completion;
- step-up completion;
- active-proof attempt start;
- out-of-band challenge issue, resend, and completion;
- configured-secret proof handling;
- weak-proof failure accounting;
- optional source provenance on satisfied proofs;
- recovery-code satisfied-proof provenance from the consumed credential instance;
- trusted-device passive credential provenance through core-owned credential ids;
- credential reset planning and execution boundaries over recovery-authority metadata;
- logout;
- session revocation;
- trusted-device revocation;
- subject-wide auth-state revocation;
- proof method declarations with method-specific online-guessing risk;
- method commit work;
- audit, mutation, precondition, durable-effect, response-effect, and fresh-secret commit
  plan separation.

Postgres runtime work exists for several early paths, including active challenge
lifecycle, session issuance/request resolution, trusted-device lifecycle paths, revocation
paths, race/stale-boundary tests, method commit work, and initial plugin registration
shapes. Treat this as an executable policy model and integration prototype, not a
production auth system.

## Final Success Criteria

Auth is not ready merely because individual reducer transitions have unit tests. Final
confidence requires a realistic adversarial application-lifecycle test suite.

The release-quality auth system should include a fictitious but realistic application that
mounts Paranoid through the intended public configuration surface and exercises a full
lifetime of subjects and credentials. That test application should simulate normal use,
recovery, device churn, credential changes, destructive actions, and attacks through the
same handlers and middleware an application would actually mount.

The lifecycle suite should cover, at minimum:

- initial registration and subject creation through multiple supported methods;
- login with and without trusted devices;
- session refresh, safe-read windows, expiry, logout, remote logout, and subject-wide
  revocation;
- step-up for sensitive actions;
- adding, replacing, resetting, and removing credentials without factor collapse;
- email or out-of-band identifier changes;
- TOTP, recovery-code, passkey/WebAuthn, message-signature, and federated-identity shapes
  once those methods exist;
- delayed deletion and delayed credential reset with notices, cancellation, expiry, and
  stale execution attempts;
- admin/support recovery intervention with audit, notices, waits, and post-action
  revocation;
- durable delivery retries, idempotency, crash-window resistance, and no response effects
  on failed commit;
- replayed cookies, copied cookies, stale challenge completions, wrong proofs, weak-gate
  failures, race attempts, concurrent rotations, and state loaded before revocation;
- email/account/method enumeration resistance;
- connection-pooler-safe Postgres behavior, byte-stable schema semantics, and bounded
  database work on hot paths.

The suite should be adversarial, not a happy-path demo. It should prove that the mounted
system preserves the same invariants the lower core claims to model, including fast-fail
before state load, database-authoritative success, atomic durable effects, and
runtime-owned cookies and secrets.

## Not Built Yet

- Finished public auth API.
- Real published middleware/endpoint helpers.
- One-configuration mounted auth runtime that wires middleware, endpoint handlers,
  cookies, CSRF, storage, durable effects, and first-party methods.
- Complete Postgres schema/migration validation for production.
- Queue-backed durable delivery integration for every effect class.
- Complete first-party method plugins.
- Mature-crate-backed TOTP, WebAuthn/passkey, OIDC, or SAML implementations.
- Complete credential lifecycle and recovery policy layer, including add/remove/replace
  credential flows, concrete method reset implementations, mounted deletion waits, mounted
  subject-deletion integration, and admin/support intervention.
- Full audit coverage matrix.
- Realistic adversarial application-lifecycle test suite through the mounted public
  runtime.
- Public documentation.
