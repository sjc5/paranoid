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

Mounted runtime construction must reject incomplete security-effect configuration.
Read-only routes such as authenticated credential inventory can stand alone. Routes that
can commit out-of-band delivery, security notices, method-owned delivery, or app-owned
subject data lifecycle work must be configured together with the Paranoid durable-effect
worker integrations. It is not acceptable to mount mutation or recovery routes that can
enqueue security-significant work while leaving the corresponding worker callbacks absent
or application-owned by convention.

Mounted credential mutation routes that need method-owned verifier, secret, replacement,
rotation, reset, or regeneration work must also be backed by an auth method registry.
Routes whose target method is named in configuration validate that exact method at runtime
construction. Routes whose target method is selected later from authoritative credential
metadata still require a registry to exist at construction; the specific method remains
validated inside the transaction when the target credential is loaded.

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

The auth web transport owns cookie emission constraints. Session, trusted-device,
active-proof challenge, and active-proof continuation cookies are all rendered through one
bounded `Set-Cookie` header path. If a method-specific challenge payload would make an
auth cookie exceed the single-cookie browser budget, Paranoid rejects the response instead
of emitting an unusable oversized cookie and hoping the browser preserves it.

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

Custom method support, if it exists after public alpha, must be a reviewed registry
contract rather than public low-level constructors. A method plugin may declare its proof
family, method label, online-guessing risk, schema, verifier hooks, challenge hooks,
method-owned commit work, and method-owned durable-effect hooks. It must not decide core
proof semantics, proof-stack sufficiency, lifecycle authority, session or trusted-device
lifecycle, cookie or CSRF effects, audit events, revocation policy, active-proof
continuation validity, weak-gate verification facts, or delivery ordering. Public alpha
should ship first-party methods only; arbitrary application-supplied methods can wait
until the registry boundary is strong enough to preserve the same invariants.

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

### Out-Of-Band Identifier Change Policy

Changing an email address, phone number, or other out-of-band identifier is credential
lifecycle work, not an application profile update. An out-of-band identifier can bind a
subject, receive login challenges, receive security notices, and act as an effective
recovery authority for other credentials. Letting applications update that binding by
convention would let them collapse factors or bypass notices without the core seeing it.

Out-of-band identifiers remain proof sources, not app-owned credential instances. An email
OTP proof source is not a password verifier, TOTP secret, passkey credential, or
recovery-code set. Identifier change should therefore be modeled as a subject/source
lifecycle mutation over Paranoid-owned identifier bindings and lifecycle-authority source
rows, not as fake credential replacement.

The core policy is:

- proof of the new identifier is required before the binding can become active;
- proof of the new identifier only proves reachability/control of that new endpoint;
- proof of the new identifier must never, by itself, authorize changing the subject;
- authorization to change the identifier must come from the current subject context, such
  as a fresh authenticated session, an accepted independent proof stack, a matured delayed
  pending action, or a scoped admin/support intervention;
- when the subject already has stronger independent credentials, an old-email-only or
  otherwise non-independent authority cannot instantly replace the recovery identifier; it
  must either be accompanied by accepted independent proof or become a delayed pending
  action with notices and cancellation;
- the identifier binding mutation, recovery-authority source update, audit event, security
  notices, and any pending-action closure must commit atomically;
- successful execution revokes existing subject auth state, because recovery and login
  routing changed;
- applications may provide delivery/canonicalization integrations, but they must not write
  identifier bindings, lifecycle-authority source rows, notices, or revocation policy
  directly.

The intended mounted flow is:

1. A live subject requests an identifier change.
2. The runtime requires the configured freshness and proof policy for this transition.
3. The runtime issues a challenge to the candidate new identifier through the configured
   out-of-band method.
4. Completion verifies the candidate identifier challenge using the normal fast-fail
   out-of-band path.
5. The runtime evaluates the current subject's lifecycle authority for identifier change.
6. If policy authorizes immediate execution, Paranoid atomically activates the new
   identifier binding, retires or supersedes the old binding, moves or recreates the
   lifecycle-authority source mapping, audits, sends notices to the old and new reachable
   channels where configured, revokes subject auth state, and clears or rotates response
   cookies as needed.
7. If policy requires a wait, Paranoid creates a subject-targeted delayed pending action
   that stores only Paranoid-owned state needed to execute the already-proven candidate
   change later. Execution revalidates the pending action and binding preconditions before
   applying the same atomic mutation and revocation.

Identifier change is not the same as account recovery. If a user has lost access to the
old identifier and has no live session, the flow must enter the recovery/support policy
surface: recovery codes, independent credentials, delayed recovery, or admin/support
intervention. A public "change my email because I can prove this new email" endpoint would
be a takeover primitive.

Delayed identifier change uses the subject-lifecycle pending-action family, not the
credential-targeted pending-action family. Execution preconditions must prove:

- the pending subject action is still open, mature, unexpired, subject-matched, and action
  matched as `ChangeOutOfBandIdentifier`;
- the old identifier binding or recovery-authority source being replaced still matches the
  state observed when the pending action was scheduled, unless the configured policy
  explicitly accepts an already-superseded no-op;
- the candidate identifier proof or reservation is still valid under the method-owned
  binding contract;
- no conflicting active binding or open pending identifier-change action has made the
  execution ambiguous;
- method-owned binding work, lifecycle-authority source updates, audit, notices, pending
  action closure, and subject-auth-state revocation commit atomically.

Cancellation of an open, unexpired delayed identifier change is explicit and noticeful.
Expiry is deadline-derived; cleanup may quietly close expired pending actions, but expiry
must not execute the change and must not be reported as user cancellation.

The current WIP lower-core implementation has Paranoid-owned Postgres rows for out-of-band
identifier bindings and subject lifecycle authorities. Immediate lower-core execution
supersedes the current binding, activates the already-proven candidate binding, replaces
the candidate source's lifecycle-authority rows with authority rows derived from the
current source, raises subject auth-state revocation, audits, and schedules a security
notice in one commit. The replacement is intentional: activating a candidate identifier
must not union preexisting candidate-source authority mappings with the current source's
authority mapping, because stale candidate mappings could silently widen future recovery
power. The email OTP method can now reserve a pending candidate identifier binding through
a runtime-owned challenge completion path: the runtime verifies the encrypted challenge
cookie and response secret before state load, the method registry resolves the candidate
source from method-owned challenge state, the commit consumes the method challenge, and
the core stores only a pending binding for the already-authenticated subject. The
authenticated immediate and delayed identifier-change Postgres runtime facades now derive
the live subject, current binding, candidate binding, step-up freshness, lifecycle
authority, and pending-action schedule internally. Matured delayed execution loads the
stored subject-lifecycle pending action inside the runtime, closes it, rechecks current
and candidate binding preconditions, activates the candidate, replaces candidate lifecycle
authority from the current source, revokes subject auth state, audits, and schedules
notice atomically. Authenticated cancellation requires fresh step-up before loading the
pending action, closes only an open unexpired action for the live subject, audits, and
schedules cancellation notice. A private mounted subject-lifecycle service now wraps
authenticated planning, authenticated immediate execution, matured delayed execution, and
authenticated cancellation for identifier changes. That mounted boundary accepts only time
plus source handles or pending-action handles, not lifecycle context, candidate authority
ids, pending-action records, notices, method work, or revocation choices. Concrete public
routes and old/new channel notice rendering remain implementation work.

The lower-core identifier-change command still carries candidate recovery-authority ids as
explicit internal planning material because it has no storage access. Runtime-facing
Postgres inputs must not accept those ids from request-shaped code. The authenticated
Postgres runtime derives the activated candidate source's effective recovery authorities
from the current active identifier source being replaced, then passes that derived set to
the lower core. That preserves the current binding's recovery-authority semantics and
prevents an identifier-change request from silently remapping which effective authority
can reset or recover other credentials.

Future mounted identifier-change policy can add an explicit Paranoid-owned policy hook if
a product truly needs to change effective recovery-authority mapping during an identifier
change. That hook must be reviewed as credential lifecycle policy, not exposed as a
request field.

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

The lower-core admin/support intervention model is now deliberately scoped. A verified
credential-lifecycle intervention carries:

- a stable intervention id recorded as a lifecycle authority source;
- the subject it may affect;
- the target credential instance it may affect;
- the exact credential lifecycle action it may authorize;
- the time it was verified and the time it expires.

Lifecycle evaluation rejects an admin/support intervention if it is expired, not yet
usable, aimed at a different subject, aimed at a different credential, or aimed at a
different lifecycle action. The intervention id is not a proof source id, and a matching
id in the lifecycle authority-source table is not enough by itself. The typed verified
intervention must also match the loaded target/action at the current transition time.

This is still lower-core and private Postgres runtime shape, not the final mounted support
product. The private runtime now owns candidate request, approval, denial, expiry, audit,
notice, and immediate-vs-delayed lifecycle handoff over stored intervention rows. The
mounted product still needs concrete route/service implementation, durable delivery
integration, user-visible rendering, and application-facing authorization hook wiring
without exposing credential mutation helpers to applications.

The mounted workflow should be staged as Paranoid-owned lifecycle work:

1. A support/admin request creates or references an intervention candidate scoped to one
   subject, one target credential, one lifecycle action, and one support policy.
2. Support-side verification and approval must mint a
   `VerifiedAdminSupportCredentialLifecycleIntervention` internally. Applications may
   provide staff-authorization facts or callbacks, but they must not construct the
   verified intervention, lifecycle context, pending action, audit event, or notice.
3. Denial closes the intervention candidate with an immutable audit event and any
   configured notice. It must not mutate credentials or create pending actions.
4. Expiry is deadline-derived. An expired unapproved intervention cannot authorize
   lifecycle work. Cleanup may close expired candidates, but it must not silently convert
   them into denial or approval.
5. Approval enters the normal credential lifecycle decision boundary. Policy decides
   whether the intervention may authorize immediate follow-on execution or must schedule a
   delayed pending action with durable notice and cancellation/expiry semantics.
6. Successful execution of support-mediated credential mutation uses the same execution
   contracts as other credential lifecycle actions and raises subject auth-state
   revocation when that transition class requires it. The mounted API must not accept a
   caller-provided "preserve sessions" override.

The current lower-core and private Postgres runtime implementation covers candidate
storage plus the approval-to-lifecycle-planning handoff: request creates a scoped
candidate row, denial closes it without credential mutation, expiry is deadline-derived,
approval verifies the candidate at runtime and feeds typed intervention evidence into the
lifecycle decision boundary, and stale/replayed candidates are rejected by commit-time
preconditions. It rejects support claims unless the typed verified intervention is live at
the transition time and scoped to the exact subject, credential, and action. It also emits
distinct audit and security-notification kinds for request, approval, denial, expiry,
immediate support authorization, and delayed support scheduling.

The mounted admin/support product boundary is now defined as a Paranoid-owned workflow,
not as lower-core mutation helpers. Mounted route/service code should load the stored
candidate, present only scoped candidate facts plus the requested staff action to an
application staff-authorization callback, and accept only an authorize/reject decision
from that callback. The callback may decide whether the staff/support actor is allowed to
approve or deny that exact candidate. It must not construct
`VerifiedAdminSupportCredentialLifecycleIntervention`, lifecycle context, pending-action
records, method work, audit events, durable notices, revocation policy, or response
effects.

Callback rejection is not the same as denying an intervention. If staff authorization
rejects, the mounted route should return an authorization failure without closing the
candidate. Denial is a separate authorized staff action that closes the candidate without
credential mutation. Expiry cleanup is not a staff decision at all; it is derived from the
stored deadline. Approval, denial, and expiry all flow through the private Postgres
runtime facades so Paranoid still owns candidate preconditions, typed intervention
construction, lifecycle planning, notices, audit, and response materialization.

Mounted responses should surface only committed runtime outcomes: intervention requested,
immediate approval authorized, delayed approval action scheduled, intervention denied, or
intervention expired. Rendered response type names distinguish immediate authorization
from delayed-action scheduling. User-visible notices are security-significant durable
effects committed with the underlying transition. Public route handlers may render those
committed outcomes for users and support staff, but they must not report an approval,
denial, expiry, notice, or pending action before the corresponding auth transition
commits.

The private WIP mounted admin/support Postgres service now implements that sequencing over
the private Postgres runtime. It requests candidates, loads candidate snapshots for staff
approval/denial callbacks without holding an auth transaction across application code,
treats callback rejection as no mutation, delegates authorized approval/denial and
deadline-derived expiry to the private runtime facades, and maps only committed
admin/support outcomes into mounted response kinds.

Approved delayed credential-targeted actions execute through a separate private mounted
credential-lifecycle service. That service loads the stored pending action, derives the
action kind from authoritative state, accepts only bounded method payloads appropriate for
that stored action, and delegates reset, replacement, regeneration, or removal execution
to private Postgres runtime facades. It does not expose pending-action records,
lifecycle-authority facts, method commit work, or caller-provided revocation policy. The
top-level private mounted route service now also has opt-in delayed credential lifecycle
execution routes for reset, replacement/regeneration, and removal. Those routes advertise
fixed paths in the route manifest, verify CSRF before body collection, parsing, or storage
work, parse only route-selected bounded JSON bodies, derive the action from the stored
pending action, and render only coarse committed outcomes without exposing subject, target
credential, or pending-action ids.

Delayed subject-auth-state deletion now has the same private mounted boundary for the
auth-owned portion of the transition. The mounted subject-lifecycle service delegates
authenticated scheduling, execution, and authenticated cancellation to the private
Postgres runtime. Scheduling derives the subject from the live authenticated session,
requires configured step-up freshness, generates the pending action id and timing from
policy, accepts no request body, and returns only coarse execution windows. Execution and
cancellation expose only committed subject-deletion outcomes. The mounted boundary
preserves the durable security notices committed by the lower-core transition and never
accepts caller-provided subject ids, pending-action schedule facts, lifecycle authority,
or revocation choices.

Mounted subject-auth-state deletion now also has a public-shaped app-owned subject data
integration boundary. The mounted execution input chooses one bounded app data lifecycle
action, currently delete subject data or disable subject data. The lower-core execution
transition commits that action as a core durable effect in the same atomic transaction as
pending-action closure, subject auth-state revocation, audit, and the security notice. The
mounted durable-effect worker then delivers the committed app data lifecycle request
through Paranoid Queue to an application integration callback.

The application callback receives committed, non-secret facts only: durable effect id,
idempotency key, Queue job context, action, subject id, and requested-at timestamp. It
does not receive pending-action records, lifecycle authority, auth-state mutation work,
revocation policy, cookies, proof facts, or method internals. It cannot make auth-state
deletion succeed, fail, or change revocation behavior. Its provider result maps through
Queue success, retry, or dead-letter behavior, so app-owned deletion/disable integration
is recoverable instead of being a best-effort after-commit callback.

Concrete public routes, public application staff-auth callback configuration, and
user-visible rendering remain implementation work.

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

The explicit allowance is the `NotRequired` independent-evidence policy on a concrete
credential or subject lifecycle transition. It is not a plugin declaration, request flag,
method label shortcut, or application-supplied override. With the default safer shape,
same-authority evidence can schedule a delayed action but cannot execute immediately when
independent evidence is required. A transition may choose `NotRequired` only when the
product semantics intentionally accept same-authority proof for that lower-risk action.

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
- a Paranoid-shaped admin/support intervention scoped to one credential lifecycle action.

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
- immediate admin/support intervention is an explicit, scoped recovery authority, not an
  invisible side door.

The production Postgres core now has first-class reducer-owned storage for this metadata:

- credential-instance rows store subject id, credential-instance id, credential kind,
  method label, reset policy role, and lifecycle state;
- credential recovery-authority rows store target credential id, lifecycle action,
  effective recovery authority id, and whether the authority is immediate or delayed;
- lifecycle authority-source rows map verified proof sources, authenticated sessions, and
  scoped admin/support intervention ids to effective recovery authority ids;
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
application-shaped shortcuts. The general web runtime rejects direct credential-reset and
credential-replacement planning and execution commands, and it also rejects direct
credential-removal planning and execution commands. Authenticated reset planning derives
the live session and lifecycle authority inside the runtime, loads the target credential
lifecycle decision in the transaction, and generates any pending-action id internally.
Unauthenticated recovery reset has two intentionally separate runtime lanes. Delayed
scheduling derives lifecycle evidence from a validated `RecoverOrReplaceCredential`
active-proof attempt, verifies that the attempt subject matches the target credential,
generates the pending-action id internally, and closes that active-proof attempt in the
same commit as the delayed reset schedule. If loaded policy would authorize immediate
reset, the scheduling lane rejects without consuming the recovery attempt; immediate
recovery must use the execution lane because it needs the target method's reset payload
and method-owned verifier mutation work. Immediate unauthenticated recovery reset
execution derives lifecycle evidence from the validated recovery continuation, rejects
delayed-only policy instead of silently scheduling work, asks the registered target method
to build reset work, and closes the recovery attempt in the same commit as verifier
mutation, audit, notice, and subject-auth-state revocation. Authenticated reset execution
derives the live session and lifecycle authority inside the runtime, loads the target
credential lifecycle decision in the transaction, and asks the registered method plugin to
build method-owned reset work for the target credential. Authenticated replacement
planning uses the same runtime-owned lifecycle-authority boundary: immediate planning
records authorization and notice without revoking auth state, while delayed planning
generates the pending replacement action internally. Authenticated immediate replacement
execution derives lifecycle authority from the live session, asks the registered target
method to build method-owned replacement work, supersedes the old credential, raises
subject auth-state revocation, audits, and schedules notice. Authenticated removal
planning derives lifecycle authority from the live session, records immediate
authorization or internally generates a delayed removal action, and does not revoke auth
state until removal executes. Authenticated immediate removal execution derives lifecycle
authority from the live session, forbids method-owned work in the current contract,
revokes the target credential, raises subject auth-state revocation, audits, and schedules
notice. Authenticated immediate rotation execution derives lifecycle authority from the
live session, asks the registered target method to build method-owned rotation work,
preserves the target credential lifecycle state, raises subject auth-state revocation,
audits, and schedules notice. Authenticated regeneration planning derives lifecycle
authority from the live session, records immediate authorization or internally generates a
delayed regeneration action, and does not generate recovery codes or method-owned
regeneration work during planning. Authenticated immediate regeneration execution derives
lifecycle authority from the live session, rejects stale step-up before target or method
work, asks the registered target method to build regeneration work, preserves the target
credential metadata, raises subject auth-state revocation, audits, schedules notice, and
releases generated recovery-code response material only after commit. Matured pending
reset, replacement, removal, and regeneration execution load the pending action and target
credential inside the transaction, verify that the pending action is still executable
during commit, and obtain method-owned work from the registered target method only for
actions whose contract requires it. Applications do not pass `method_commit_work`,
pending-action authority, satisfied lifecycle authority facts, or preassembled
reset/replacement/removal/rotation/regeneration planning or execution commands through
these facades.

These private unauthenticated recovery reset lanes are downstream of an already validated
`RecoverOrReplaceCredential` active-proof continuation. The current private runtime also
has the first no-session recovery ceremony slice for recovery codes: it starts an unbound
`RecoverOrReplaceCredential` attempt only after runtime-owned preflight, accepts a sealed
recovery-code response through the recovery-code method registry, uses the sealed payload
only as a candidate subject before state load, consumes the authoritative one-time
recovery-code row before recording proof success, and only then binds the attempt to the
resolved subject. Proof acceptance reissues the active-proof continuation cookie with the
same presented continuation secret but with a proof-bound subject marker in the encrypted
payload. A runtime-bound subject marker means only that the attempt started from an
already-known runtime context, such as a live session; it is not recovery authority.
Delayed recovery reset scheduling and immediate recovery reset execution must consume the
accepted proof-bound continuation; unbound start cookies and runtime-bound subject
continuations are not accepted for those lifecycle transitions.

That is still a private runtime and mounted-service boundary, not the final public mounted
auth product. Public route rendering, public request/response types, input limits, cookie
budgets, CSRF behavior, concrete public reset/replacement/rotation UI flows, remaining
first-party method-specific lifecycle implementations, public mounted removal routes, and
public mounted deletion routes remain future work.

Admin/support intervention and pending-action commands should consume this boundary
instead of reimplementing factor-collapse checks. Reset, rotation, and regeneration
currently preserve the target credential's core-visible metadata and recovery-authority
graph. Method plugins can commit method-owned verifier, secret, or recovery-code-set work
and post-commit response material, but they cannot create core credential metadata,
recovery-authority rows, or lifecycle authority-source rows through method work.
Replacement is different: it creates a core-visible successor credential, so the core
validates the successor shape and storage enforces the after-state posture guard at commit
time. The private mounted credential-lifecycle service now also wraps the delayed
unauthenticated recovery scheduling and immediate-reset execution paths: the safer mounted
recovery target path provides a configured reset target method rather than a
request-supplied credential id. The runtime resolves the one active target credential for
the recovered subject, proof family, and method label inside the same transaction that
plans or executes the reset. Missing or ambiguous targets reject instead of letting the
caller choose. Immediate execution also provides the target method's bounded reset
payload. The runtime derives lifecycle evidence from the validated
`RecoverOrReplaceCredential` active-proof continuation and consumes that attempt
atomically only with delayed scheduling or immediate reset execution.

The continuation used by these reset lanes is the proof-bound recovery continuation
emitted after recovery proof success, not the unbound start continuation and not a
runtime-bound continuation from a logged-in context. This lets the runtime reject missing,
expired, wrong-use, unbound, or runtime-bound recovery continuations before loading state
while preserving database-authoritative success for the pending action or reset commit.

The private mounted no-session recovery surface is grouped by one configured recovery
flow: a configured recovery proof method and a configured reset target method. Start,
proof completion, delayed reset scheduling, and immediate reset execution all derive their
runtime inputs from that flow. The mounted no-session path does not accept target
credential ids, lifecycle authority facts, proof-sufficiency facts, method commit work, or
raw cookie material from application-shaped requests. Submitted preflight material,
recovery proof material, delayed-reset scheduling material, and target-method reset
payload bytes enter through route-specific request body types. Each body type constructs
exactly one recovery route step through bounded, redacted wrapper types before runtime
input construction. Route-shaped code provides time plus preflight or raw request bytes;
it does not pass prebuilt lower recovery-proof or reset-payload wrappers.

The private Postgres no-session recovery reset runtime lane follows the same target rule.
It resolves one active target credential by configured method for the recovered subject
inside the transaction. It does not expose a credential-id reset helper for no-session
recovery. Missing or ambiguous configured targets reject without consuming the recovery
attempt. The delayed scheduling and immediate execution lanes both reject missing,
expired, wrong-use, unaccepted, and runtime-bound recovery continuation cookies before
storage work, and the operation-count tests pin that pre-state boundary. Delayed
scheduling and immediate execution consume the accepted proof-bound recovery attempt
atomically with the committed reset transition. Replaying the same accepted recovery
continuation after scheduling or execution cannot schedule another pending action, commit
duplicate method work, enqueue duplicate notices, advance revocation, or resurrect the
consumed attempt.

The private mounted no-session recovery route-shaped layer hides lower-core details from
the eventual user-facing route response. It maps recovery start to an expiry time without
exposing the attempt id, maps proof acceptance/rejection without exposing proof summaries,
attempt ids, or deletion flags, maps delayed reset scheduling without exposing subject or
target credential ids, and maps immediate reset execution without exposing subject or
target credential ids. The route-step policy also separates the ceremony guards: start
requires challenge-issue preflight; proof completion requires submitted recovery secret
material; delayed reset scheduling and immediate reset execution require CSRF because they
consume ambient active-proof continuation cookie authority. The private mounted service
now has one normal route request executor that returns only a mounted route response:
route outcome plus rendered `Set-Cookie` headers. A narrower configured route service owns
the recovery flow and exposes route-specific HTTP entry points whose Rust body types
correspond to exactly one route step: start, proof submission, delayed reset scheduling,
or immediate reset execution. Endpoint-shaped code therefore does not pass proof method
config, reset target config, or an erased any-step body on each request. That shape
removes the erased any-step body path instead of relying on a runtime step/body mismatch
check. The configured route service now also has a single endpoint-shaped request handler:
method and path select the mounted recovery endpoint, the typed request body must match
that endpoint's step, mismatches reject before CSRF or storage work, and successful
execution returns an `http::Response` whose body is the user-visible route body and whose
headers include the rendered `Set-Cookie` values. A separately named internal inspection
path can return the lower runtime execution for tests, but future route code should not
need access to runtime executions or individual lower route helpers. The direct per-step
recovery route helpers are test-only inspection conveniences; production route-shaped code
enters through the mounted guarded endpoint path. The route executor verifies Paranoid
CSRF request state before running the continuation-cookie reset scheduling or execution
steps, and missing CSRF rejects before auth storage work. Concrete route request-body
constructors enforce the same bounded payload types that the runtime uses: bounded
weak-gate preflight material, bounded recovery secret material, an explicitly empty
schedule-reset body, and bounded target-method reset payload material. Concrete route
response bodies are projected from committed route outcomes. That body projection drops
the internal pending-action id from delayed reset scheduling while preserving the
user-needed execution and expiry times. In normal builds, the mounted no-session recovery
route outcome itself also drops that pending-action id; lower pending-action ids remain
available only to tests that inspect the boundary. The rendered no-session recovery body
type strings use the `credential_recovery_*` namespace so recovery reset outcomes do not
look like generic credential-reset route outcomes. Successful recovery-proof completion
now issues a CSRF token cookie only after the proof acceptance transition has committed,
so the following reset scheduling or immediate reset request can present CSRF without
application code manually issuing auth-route CSRF material. Concrete public route
registration, full automatic CSRF token cycling for every mounted auth mutation, cookie
budget tests beyond current auth-cookie families, and final rendering remain future
mounted-runtime work.

The top-level private mounted auth route service now also has a submitted-body boundary
above the no-session recovery route bodies. It owns the mount path, selects the configured
auth endpoint from method and path, rejects unknown mounted routes before body validation
or storage work, verifies the submitted body belongs to the selected route step, and only
then converts submitted material into the bounded typed recovery body. This keeps
endpoint-shaped code from preassembling recovery-proof wrappers, reset-payload wrappers,
lifecycle authority, target credential ids, method work, or proof-sufficiency facts while
still avoiding commitment to the final public HTTP wire format.

The private mounted full-authentication route vocabulary now models the unauthenticated
out-of-band start, out-of-band proof submission, and full-authentication completion
endpoints. The collected HTTP body parser accepts only strict JSON for the selected
endpoint, decodes byte fields from canonical base64url, carries weak-gate response
material as opaque runtime-verifier input, bounds trusted-device display labels, and
rejects trusted-device display labels unless trusted-device creation was requested. The
private mounted route service advertises those endpoints only when the mounted runtime
config names the full-authentication out-of-band method and the runtime validates that
method against the registered method plugins.

The private Postgres runtime now has a method-registry start-derivation contract for
out-of-band full-authentication start: route-shaped code supplies only bounded
method-start payload, and the registered method derives recipient handles, delivery dedupe
buckets, cooldown identity, and delivery idempotency inside Paranoid before the fused
attempt/challenge transaction begins. Email OTP is the first concrete method on that
boundary. Applications must not submit those delivery facts directly, and route-shaped
code must not preassemble challenge cookies, proof-sufficiency facts, lifecycle authority,
or method-owned commit work.

PgBouncer-backed mounted HTTP coverage now executes the configured email OTP
full-authentication route end to end: mounted start issues the attempt/challenge through
the method-derived boundary, mounted proof completion records the satisfied proof through
the out-of-band fast-fail path, and mounted completion creates the session and optional
trusted-device credential. The route-layer test pins the same exact database-operation
sequences as the private runtime facades, so route parsing and response projection cannot
silently add storage work. The same route-layer coverage now also pins duplicate mounted
start behavior for a live delivery dedupe bucket: the route returns the same accepted
public body shape as a fresh start, emits no cookies, rolls back fresh attempt/challenge
work, and enqueues no additional delivery.

The private mounted auth route service now also has an authenticated credential inventory
route. This route derives the subject from the live session cookie, loads only active
credential metadata for that subject, and returns opaque credential handles plus safe
method/role labels for lifecycle targeting. It does not expose subject ids, recovery
authority graphs, lifecycle context, method-owned state, or mutation authority.
Applications should use this Paranoid-owned handle presentation path rather than querying
auth tables or inventing lifecycle target handles.

The top-level private mounted auth route service now also has the first authenticated
credential-lifecycle HTTP route family: configured credential addition. A mounted
credential-addition route is keyed by an explicit path-safe route segment, not by a raw
method label, because method labels are not URL path segments. The mounted runtime config
owns the route segment plus the configured `MountedCredentialAdditionMethod`; requests
cannot supply lifecycle authority, authority graphs, credential ids, method work,
revocation choices, or response-cookie material. The route verifies CSRF before body
collection or parsing, parses one bounded base64url method payload, dispatches to the
configured method through the mounted lifecycle service, appends committed runtime
`Set-Cookie` effects, hides subject and credential ids from the route response body, and
renders generated recovery codes only through the committed post-commit response-material
handoff when the configured method creates them. PgBouncer-backed route coverage currently
pins missing-CSRF rejection before storage work and successful password-derived credential
addition through the registered method plugin.

The same private mounted route service now has authenticated credential-reset planning and
immediate-execution routes. These routes are opt-in on the mounted runtime config while
auth is private WIP. Requests cannot supply lifecycle authority, policy decisions, subject
facts, pending-action records, method work, revocation choices, or response-cookie
material. The plan route accepts only the opaque credential handle returned by
authenticated credential inventory. The immediate execution route accepts that credential
handle plus bounded method-specific reset payload. Both routes verify CSRF immediately
after route selection and before body collection, parsing, or storage work. Route
responses project only committed outcomes: reset immediate authorization, delayed reset
action scheduled with execution windows, reset executed, needs full authentication, or
needs step-up. Rendered response type names distinguish immediate authorization from
delayed-action scheduling. They do not expose subject ids, target credential ids, or
internal pending-action ids. PgBouncer-backed route coverage pins missing-CSRF rejection
before storage work and successful password-derived verifier reset through the registered
method plugin.

The same private mounted route service now has authenticated credential-replacement
planning and immediate-execution routes. These routes are opt-in on the mounted runtime
config while auth is private WIP. Requests cannot supply lifecycle authority, policy
decisions, subject facts, pending-action records, successor credential ids, method work,
revocation choices, or response-cookie material. The plan route accepts only the opaque
credential handle returned by authenticated credential inventory. The immediate execution
route accepts that credential handle plus bounded method-specific replacement payload.
Both routes verify CSRF immediately after route selection and before body collection,
parsing, or storage work. Route responses project only committed outcomes: replacement
immediate authorization, delayed replacement action scheduled with execution windows,
credential replaced, needs full authentication, or needs step-up. Rendered response type
names distinguish immediate authorization from delayed-action scheduling. They do not
expose subject ids, target credential ids, successor credential ids, or internal
pending-action ids. PgBouncer-backed route coverage pins missing-CSRF rejection before
storage work and successful replacement through the registered method plugin: the target
credential is superseded, a successor credential is created, a security notice commits,
and subject auth state is revoked.

The same private route pattern now covers authenticated credential-removal planning and
immediate execution. These routes are opt-in on the mounted runtime config while auth is
private WIP. Requests cannot supply lifecycle authority, policy decisions, subject facts,
pending-action records, method work, revocation choices, or response-cookie material. Both
routes accept only the opaque credential handle returned by authenticated credential
inventory and verify CSRF immediately after route selection and before body collection,
parsing, or storage work. Route responses project only committed outcomes: removal
immediate authorization, delayed removal action scheduled with execution windows,
credential removed, needs full authentication, or needs step-up. Rendered response type
names distinguish immediate authorization from delayed-action scheduling. They do not
expose subject ids, target credential ids, or internal pending-action ids.
PgBouncer-backed route coverage pins missing-CSRF rejection before storage work and
successful removal through the real commit-time posture guard: the target credential is
revoked, an independent survivor stays active, a security notice commits, and subject auth
state is revoked.

The same private route pattern now covers authenticated credential-rotation immediate
execution. This route is opt-in on the mounted runtime config while auth is private WIP.
Requests cannot supply lifecycle authority, policy decisions, subject facts, method work,
revocation choices, or response-cookie material. The route accepts only the opaque
credential handle returned by authenticated credential inventory plus bounded
method-specific rotation payload, verifies CSRF immediately after route selection and
before body collection, parsing, or storage work, dispatches through the mounted
credential lifecycle service, and projects only committed outcomes: credential rotated,
needs full authentication, or needs step-up. It does not expose subject ids or target
credential ids. PgBouncer-backed route coverage pins missing-CSRF rejection before storage
work and successful rotation through the registered method plugin: the target credential
remains active, its recovery-authority graph is preserved, a security notice commits, and
subject auth state is revoked.

The same private route pattern now covers authenticated credential-regeneration planning
and immediate execution. These routes are opt-in on the mounted runtime config while auth
is private WIP. Requests cannot supply lifecycle authority, policy decisions, subject
facts, pending-action records, generated recovery codes, method work, revocation choices,
or response-cookie material. The plan route accepts only the opaque credential handle
returned by authenticated credential inventory. The immediate execution route accepts that
credential handle plus bounded method-specific regeneration payload. Both routes verify
CSRF immediately after route selection and before body collection, parsing, or storage
work. Route responses project only committed outcomes: regeneration immediate
authorization, delayed regeneration action scheduled with execution windows, credential
regenerated with generated recovery codes only from committed post-commit material, needs
full authentication, or needs step-up. Rendered response type names distinguish immediate
authorization from delayed-action scheduling. They do not expose subject ids, target
credential ids, or internal pending-action ids. PgBouncer-backed route coverage pins
missing-CSRF rejection before storage work and successful recovery-code regeneration
through the registered method plugin: the target credential remains active, its
recovery-authority graph is preserved, a security notice commits, subject auth state is
revoked, and newly generated recovery codes are projected only after the storage commit.

Shared mounted HTTP coverage now also proves that authenticated credential addition,
reset, replacement, removal, regeneration, and rotation routes with valid CSRF but no live
session authority return `needs_full_authentication` before storage work and do not expose
target or method-work oracles. Missing session cookies emit no `Set-Cookie` headers.
Expired session cookies are cleared without storage work.

Direct Postgres runtime coverage pins the same no-live-session, no-storage boundary for
authenticated out-of-band identifier change, pending credential-action cancellation,
subject-auth-state deletion scheduling and cancellation, and pending identifier-change
cancellation facades. Missing session cookies emit no `Set-Cookie` headers. Expired
session cookies are cleared without storage work. Matured delayed execution remains
intentionally separate because the durable pending action, not a live session, is the
authority for that path.

The same private route pattern now covers authenticated out-of-band identifier-change
planning, immediate execution, delayed execution, and delayed cancellation. These routes
are opt-in on the mounted runtime config while auth is private WIP. Requests cannot supply
lifecycle authority, policy decisions, subject facts, candidate authority mappings,
pending-action records, notices, revocation choices, or response-cookie material. Planning
and immediate execution accept only the current and candidate identifier source handles.
Delayed execution and cancellation accept only the pending subject action handle and load
the current/candidate binding details from authoritative pending-action state. All four
routes verify CSRF immediately after route selection and before body collection, parsing,
or storage work. Route responses project only committed outcomes: identifier-change
immediate authorization, delayed identifier-change action scheduled with execution
windows, identifier changed, delayed identifier change cancelled, needs full
authentication, or needs step-up. Rendered response type names distinguish immediate
authorization from delayed-action scheduling. They do not expose subject ids, source ids,
candidate authority ids, or internal pending-action ids. PgBouncer-backed route coverage
pins missing-CSRF rejection before storage work, successful immediate execution,
successful delayed execution, successful delayed cancellation, and stale-session
cancellation returning `needs_step_up` before pending-action load.

The private mounted route service now has a framework-neutral Tower/http boundary for the
configured no-session recovery flow. Method and path selection happen before body
collection. Unknown mounted routes reject before body validation or storage work.
CSRF-required reset routes verify CSRF immediately after route selection and before body
collection, body parsing, or storage work. The service then collects the request body
behind a configured byte limit, parses only the route-selected shape, requires
`Content-Type: application/json` for JSON routes, decodes byte payload fields from
canonical base64url, preserves the delayed reset scheduling route as explicitly
empty-body, and renders only coarse JSON success/error responses plus committed
`Set-Cookie` headers. The PgBouncer-backed mounted route test exercises this Tower
boundary for unknown routes, malformed bodies, missing CSRF, oversized bodies, and a valid
start request, and pins that these pre-runtime error responses emit no `Set-Cookie`
headers. The PgBouncer-backed no-session recovery-code route tests also prove that a
rejected proof does not receive the accepted-proof CSRF handoff cookie, that a valid CSRF
token plus the unaccepted start continuation still rejects delayed-reset scheduling and
immediate reset execution before storage work, and that the accepted-proof response's CSRF
handoff cookie can authorize the subsequent delayed-reset scheduling route. Final public
route registration, broader CSRF token cycling, and polished user-visible rendering remain
future mounted-runtime work.

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
- Credential mutation execution is subject-auth-state invalidating for the currently built
  reset, replacement, removal, and regeneration paths. Scheduling and cancellation do not
  revoke existing auth state, but execution does. Runtime-facing inputs and future mounted
  handlers must not accept a caller-provided "preserve existing sessions" flag for those
  execution paths.

Lifecycle freshness and delay policy are runtime-owned, not request-owned. Authenticated
lifecycle requests that plan a credential reset, replacement, or removal, execute an
immediate credential reset, replacement, removal, or rotation, or cancel an open delayed
credential/subject lifecycle action require a live session with fresh step-up by default.
A stale but otherwise live session receives `NeedsStepUp` before the runtime loads target
credential metadata, pending-action rows, or method-owned mutation work. The mounted API
may later expose clear policy configuration, but application requests must not carry ad
hoc booleans such as "step-up required" or arbitrary delayed execution timestamps.

Delayed execution timing is also Paranoid-owned policy. Credential reset, replacement, and
removal planning use the configured delay and expiry window when lifecycle authority says
the mutation must wait. Subject-auth-state deletion is inherently delayed and uses its
configured deletion delay and expiry window. Matured delayed execution does not require a
live session or fresh step-up, because the durable pending action, maturity deadline,
expiry deadline, and commit-time preconditions are the authority for that execution.
Cancellation is different: it is an authenticated lifecycle mutation and therefore
requires the cancelling subject to present fresh step-up under the current policy.

The reducer now has concrete non-reset pending-action execution and cancellation commands
for credential-targeted `Replace`, `Remove`, and `Regenerate` actions. These commands are
still lower-core WIP commands, not mounted application APIs. The generic web runtime
rejects direct calls to them. Their current contracts are:

- replacement execution locks the pending action and target credential, requires
  method-owned work matching the target credential family/method, closes the pending
  action, records execution, marks the old target credential `Superseded`, raises subject
  auth-state revocation, and commits a replacement notice;
- removal execution locks the subject's active credential set in deterministic order,
  requires at least one other active credential instance, locks the pending action and
  target credential, forbids method-owned work in the current contract, closes the pending
  action, records execution, marks the target credential `Revoked`, raises subject
  auth-state revocation, and commits a removal notice;
- regeneration execution locks the pending action and target credential, requires
  method-owned work matching the target credential family/method, closes the pending
  action, records execution, preserves the target credential lifecycle state, raises
  subject auth-state revocation, and commits a regeneration notice;
- cancellation for these non-reset credential-targeted actions closes only open,
  unexpired, target-matched pending actions and commits the action-specific cancellation
  audit/notice.

Concrete Postgres runtime facades now execute matured credential-targeted replacement,
removal, and regeneration actions by loading the pending row and target credential inside
the transaction. Replacement and regeneration ask the registered target-credential method
plugin to construct method-owned mutation work from an opaque runtime input payload.
Removal is core-owned, rejects method work, and has the same baseline last-active
credential guard as immediate authenticated removal. The same runtime boundary provides
authenticated cancellation for open, unexpired non-reset credential-targeted actions.
Applications still do not pass pending action records, target credential metadata,
lifecycle authority facts, or method commit work.

Delayed subject/account deletion is deliberately not forced into the credential-targeted
pending-action row. It is a subject-targeted lifecycle action. Its pending action must
target subject auth state, not a fake credential id. Execution of subject deletion
requires subject-wide auth-state revocation semantics and app-facing deletion integration
once the public mounted runtime exists. The lower core now has a dedicated subject
pending-action record, scheduling command, execution command, cancellation command,
subject-specific preconditions, subject-specific storage table contract, deletion audit
events, and deletion security notices. The Postgres runtime executes matured
subject-auth-state deletion actions by loading the pending subject action inside the
transaction, and it provides authenticated cancellation by deriving the cancelling subject
from a live session rather than caller-provided subject facts. A private mounted
subject-lifecycle service now wraps those runtime facades and surfaces only committed
execution/cancellation outcomes. Mounted execution can now request app-owned subject data
deletion or disabling as a recoverable Queue-backed durable effect committed with the
auth-state mutation.

"Second-factor reset" is also not a separate credential kind and must not be inferred from
TOTP, WebAuthn, SMS, or any other plugin label. It is a lifecycle policy role over a
credential reset transition. The same `Reset` pending-action contract can represent a
password reset, TOTP reset, passkey reset, or other verifier reset; policy decides whether
the target credential is acting as a second factor and therefore which delay, proof,
notice, and revocation requirements apply.

The current lower-core model stores this as `CredentialResetPolicyRole` on
`CredentialInstanceMetadata`. That role is authoritative credential metadata, not request
input and not method/plugin inference. Runtime-facing credential-reset paths load the
target credential metadata inside the Postgres transaction, select the reset policy from
the loaded role, and then apply that role's independence, delay, freshness, notice, and
revocation semantics. When ordinary and second-factor reset policies share the same
authenticated freshness requirement, the runtime can reject stale sessions before loading
target metadata. When those freshness requirements differ, the runtime must load the
target role before it can choose the exact freshness rule; successful mutation still
requires the selected role's policy to pass.

Second-factor reset uses the same credential-targeted `Reset` pending-action record as
other delayed credential resets. There is no separate second-factor credential kind, no
separate second-factor pending-action table, and no method-label shortcut such as "TOTP
always means second factor." A TOTP credential can be ordinary for reset policy if the
configured credential metadata says so, and a message-signature or passkey credential can
be treated as a second factor if policy says so.

### Last Strong Factor Protection

Credential lifecycle policy must protect against deleting, replacing, resetting, or
regenerating the subject into a weaker effective auth posture by accident. The current
baseline removal guard that checks for another active credential is necessary but not
sufficient as the final policy.

The final last-strong-factor check must reason about the after-state of the subject's auth
configuration, not merely count active credential rows. A remaining active credential is
not enough if it depends on the same recovery authority as the removed credential, cannot
authenticate under the configured public policy, is pending/suspended/expired, or is only
a convenience credential over a weaker recovery path.

The current removal guard is now graph-aware for the built ordinary/second-factor collapse
cases. Ordinary credential removal still requires another active access-preserving
credential. Second-factor credential removal requires another active second-factor
credential. Both paths load recovery-authority rows for the subject's active credentials
and reject an after-state where any remaining second-factor credential is immediately
resettable by the same effective authority as any ordinary access-preserving survivor
credential. Removing either credential role must not leave a credential pair that looks
two-factor but collapses to one effective authority, and a distinct survivor path must not
hide a different collapsed ordinary-plus-second-factor path. Credential replacement uses
the same after-state helper with the replacement successor included in the evaluated
survivor set. A second-factor replacement successor is rejected if its immediate reset
authority collapses to the same authority as any ordinary survivor path; a successor whose
immediate reset authority is distinct from every ordinary survivor preserves the intended
posture. Immediate and matured pending Postgres runtime tests pin this replacement posture
guard for both ordinary and second-factor targets.

Credential addition has the same honesty requirement for the new credential. Adding a
credential does not require existing collapsed state to be fixed first, because that would
block some remediation paths. But the specific addition must not introduce a new collapsed
ordinary-plus-second-factor pair: a newly added second-factor credential must be
independent from every existing ordinary access-preserving credential, and a newly added
ordinary credential must be independent from every existing second-factor credential.

For high-risk lifecycle mutations, Paranoid should ask:

- after this mutation commits, does the subject still have at least one configured
  authentication path that policy accepts for normal login or recovery;
- if the subject previously had an independent second factor, does the after-state retain
  an independent proof source or deliberately enter a delayed/support-mediated downgrade;
- do remaining credentials collapse to the same effective `RecoveryAuthorityId`;
- does the mutation revoke existing auth state and send notices when recovery posture
  changes;
- is a destructive downgrade blocked, delayed, or support-mediated rather than silently
  accepted because one row still says `Active`.

This protection applies to passkey removal, TOTP reset/removal, recovery-code
regeneration/removal, password reset/replacement where the password had independent value,
OIDC unlinking, and any future second-factor plugin. The mounted API must not expose a
caller-provided override to skip it.

## Fast-Fail Transition Matrix

This matrix is the design checklist for every auth transition. The goal is not merely to
use fast-fail where it falls out naturally. The goal is to actively search for safe
protocol shapes where impossible or abusive requests can be rejected before authoritative
storage work.

The `Current live shape` column is status, not proof. Some rows are fully implemented and
tested; some are model contracts; some are deliberately future method scopes. If a row
claims no database work before rejection, that claim needs executable operation-count or
load-boundary tests before it can be treated as pinned.

| Transition                                                           | Pre-state rejection gate                                                                                                                                                                      | Sealed or presented state                                                                                                                                                         | Authoritative work after gate                                                                                                             | Current live shape                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Safe read with fresh safe-read cache                                 | Encrypted session cookie deadline rejects expired cache without DB.                                                                                                                           | Session cookie carries session id, secret, hard session ceiling, and bounded safe-read deadline.                                                                                  | None for accepted safe reads; state-changing and sensitive requests still load state.                                                     | Modeled and covered by request-resolution/load-contract tests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Session resolution after cache miss or unsafe request                | Cookie expiry ceilings reject impossible sessions before session lookup.                                                                                                                      | Session cookie carries id and secret; storage keeps MACs and version state.                                                                                                       | Load session, classify secret, check revocation, refresh window, step-up freshness, and subject-wide revocation.                          | Modeled in reducer, Postgres runtime, and request-resolution tests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Trusted-device silent revival                                        | Trusted-device cookie expiry and silent-revival deadline reject impossible passive revival before DB.                                                                                         | Trusted-device cookie carries credential id, secret, hard credential ceiling, and silent-revival ceiling.                                                                         | Load credential, classify secret, check revocation, create session, rotate device credential.                                             | Modeled in reducer, Postgres runtime, and lifecycle tests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Start step-up active-proof attempt                                   | Session cookie expiry rejects impossible step-up starts before DB.                                                                                                                            | Session cookie supplies the current subject/session context; caller supplies no subject id.                                                                                       | Load session and subject revocation, validate session secret, create subject-bound attempt and continuation credential.                   | Runtime has current-session start facades; generic and Postgres tests prove missing sessions do not write and valid starts derive subject.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Start trusted-device active-revival proof attempt                    | Trusted-device cookie expiry rejects impossible active-revival starts before DB.                                                                                                              | Trusted-device cookie supplies the subject/device context; caller supplies no subject id.                                                                                         | Load device credential and subject revocation, validate device secret, create subject-bound attempt and continuation credential.          | Postgres lifecycle coverage starts active revival from the validated trusted-device cookie rather than a caller-supplied subject.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Trusted-device active revival                                        | Trusted-device cookie expiry and active-proof continuation cookie deadline/secret can reject impossible revival before DB.                                                                    | Trusted-device cookie supplies known subject/device context; active-proof continuation cookie supplies attempt id plus secret.                                                    | Validate device record and active-proof attempt, then issue a session and rotate device credential after proof-stack policy passes.       | Postgres runtime derives the attempt id from the continuation cookie and covers active revival through PgBouncer-backed tests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Start unauthenticated active-proof attempt and issue first challenge | Runtime-owned weak gate can reject write-amplifying challenge starts before attempt/challenge writes.                                                                                         | Challenge issue request names intended proof use and method; no app-supplied proof verification facts are accepted.                                                               | Commit attempt start and challenge issue atomically, including continuation credential, method work, and durable delivery command.        | Postgres runtime has fused start-and-issue paths with preflight verification and continuation-cookie response materialization.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Issue out-of-band challenge on an existing attempt                   | Active-proof continuation cookie deadline/secret rejects impossible challenge issue before attempt load; no caller may preassemble the fast-fail cookie.                                      | Continuation cookie carries attempt id plus secret; encrypted challenge cookie carries challenge id, proof summary, nonce, and MAC.                                               | Load attempt and subject revocation, enforce dedupe/open-attempt preconditions, store challenge, enqueue delivery.                        | Runtime derives the attempt id from the continuation cookie; Postgres method registry supplies generated response-secret material and method work.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Resend out-of-band challenge                                         | Encrypted challenge cookie must validate as an unexpired out-of-band ceremony before any DB load.                                                                                             | Same challenge cookie identifies the existing attempt and challenge; caller supplies only a fresh delivery idempotency key.                                                       | Load attempt/challenge, enforce open challenge and resend budget, append delivery work.                                                   | Postgres runtime validates cookie before loading state and obtains method work from the registry.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Complete out-of-band challenge                                       | Wrong submitted response rejects by MAC from the encrypted challenge cookie before any DB load.                                                                                               | Encrypted cookie carries response MAC and challenge context; submitted response is secret material.                                                                               | Load attempt/challenge and subject revocation, resolve subject through method state, close challenge, consume method state, record proof. | Postgres runtime verifies MAC first, then resolves subject and method work through the registry inside the post-gate transaction.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Issue message-signature challenge                                    | Runtime-issued nonce and method-sealed verifier/context must be generated during challenge issue; any necessary lookup belongs here, not on completion.                                       | Encrypted challenge cookie carries nonce and method state such as canonical-message hash or sealed verifier material.                                                             | Store any method challenge state only through method commit work if needed.                                                               | Runtime supports active-method challenge issue through the method registry. The first-party password-derived signature plugin loads the verifier during issue and seals canonical message/verifier state.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Complete message-signature challenge                                 | Signature over the bound challenge should reject before DB when verifier material was sealed at issue time; online-guessable methods must bind the weak gate to the submitted proof material. | Encrypted cookie carries proof summary, nonce, deadline, and method challenge state; weak-gate verification receives a digest of the exact challenge state plus response payload. | After signature success, load attempt/challenge and authoritative verifier/version state before accepting proof.                          | First-party password-derived signature tests prove wrong signatures reject before DB, successful signatures recheck locked authoritative verifier/version state, and a weak gate solved for one signature cannot be reused for another signature.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Issue origin-bound public-key challenge                              | Runtime-issued challenge, origin/RP context, and credential lookup context are sealed before completion.                                                                                      | Encrypted cookie carries nonce, origin/RP binding, credential/challenge state, and deadline.                                                                                      | Authoritative credential state must still validate credential status, subject mapping, and replay/sign-count rules.                       | Contract and test-plugin paths exist; mature WebAuthn/passkey plugin is not built.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Complete origin-bound public-key challenge                           | Assertion structure, origin/RP binding, and signed challenge can reject before DB when sealed challenge state is sufficient.                                                                  | Encrypted cookie carries proof identity and method challenge state.                                                                                                               | Load attempt/challenge and authoritative credential state before accepting proof or mutating counters.                                    | Test-plugin paths cover the family shape; concrete WebAuthn/passkey implementation is not built.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Issue federated-identity challenge                                   | Runtime-generated state/nonce/redirect binding rejects mismatched callbacks before subject mapping.                                                                                           | Encrypted state cookie carries issuer, audience/client, redirect binding, nonce, state, deadline, and provider context.                                                           | Authoritative issuer config, external subject mapping, and account-link policy still gate success.                                        | Contract and test-plugin paths exist; concrete OIDC/SAML implementation is not built.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Complete federated-identity assertion                                | Invalid state, nonce, issuer, audience, or assertion signature can reject before local account mapping.                                                                                       | Encrypted state cookie binds the callback to the initiated ceremony.                                                                                                              | Load attempt/challenge and authoritative mapping/linking state before accepting proof.                                                    | Test-plugin paths cover the family shape; concrete OIDC/SAML implementation is not built.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Direct known-subject TOTP                                            | Weak gate rejects before DB; direct code verification cannot reject wrong TOTP before fetching the subject verifier.                                                                          | Existing session, trusted device, or prior proof supplies the subject-bound attempt.                                                                                              | Load attempt and subject verifier, verify code, record success or weak failure.                                                           | Postgres tests assert invalid weak gates perform no DB work; wrong codes with valid gates perform the authoritative verifier lookup and spend the ceremony weak-failure budget.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Challenge-bound TOTP                                                 | Encrypted challenge cookie plus Bloom filter can reject definite non-matches before DB; weak gate must also pass before state load.                                                           | Encrypted cookie carries TOTP challenge context and Bloom bitset for the acceptable human window.                                                                                 | Possible Bloom hits still load attempt, subject revocation, challenge row, and locked authoritative verifier/version state.               | First-party Postgres runtime lane is live. Tests assert definite Bloom misses perform no DB work, valid possible hits perform authoritative lookup and record credential-instance source, stale verifier-version possible hits record failure authoritatively, and late-window accepted codes do not false-negative.                                                                                                                                                                                                                                                                                                                                                                                           |
| Recovery code                                                        | Canonical base58 parsing plus AEAD decrypt/tag verification rejects malformed or guessed sealed codes before DB; known-subject flows also reject subject mismatch before DB.                  | Opaque sealed recovery code carries subject id plus random token; no public prefix or lookup id is exposed.                                                                       | MAC the decrypted random token, lock the unused code row for that subject, and consume atomically with proof success.                     | Postgres tests assert malformed, guessed, and wrong-subject sealed tokens perform no DB work; plausible sealed-but-unused tokens perform authoritative lookup, reject, and consume nothing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Add credential                                                       | Existing session, step-up freshness, active-proof continuation, and challenge cookies reject impossible add requests before target credential work.                                           | Current session plus active proof stack identify subject and proposed credential context.                                                                                         | Evaluate lifecycle policy, verify proof independence when required, create pending or active credential, enqueue notices.                 | Lower-core transition, private authenticated Postgres runtime facade, private public-shaped mounted service, and private mounted route rendering are implemented and covered for immediate active credential creation, runtime-generated credential id, session-derived lifecycle evidence, registered method-owned creation work, recovery-authority persistence, source-authority mapping, stale step-up rejection before authority/method work, audit, notice, subject auth-state revocation, CSRF-before-storage route guarding, coarse user-visible JSON without internal lifecycle ids, and exact mounted route operation counts. Delayed add/pending activation and public exposure remain future work. |
| Replace or reset credential                                          | Existing session/trusted-device/proof cookies and weak gates reject impossible reset/replacement ceremonies before target credential lookup where possible.                                   | Active proof stack plus target credential context; authenticated replacement derives lifecycle evidence from the live session.                                                    | Evaluate dependency graph, reject collapsed factors, enforce wait/admin/recovery-code rules, reset or replace credential atomically.      | Credential reset planning/execution and authenticated credential replacement planning/immediate execution are live in lower-core/private Postgres/private mounted-service shape. Private mounted reset and replacement HTTP routes are live, CSRF-guarded before body/storage work, and covered with exact operation-count assertions. Password-derived-signature and TOTP have real first-party verifier reset/replacement coverage. Public route rendering and remaining method-specific lifecycle implementations remain future work.                                                                                                                                                                       |
| Remove credential                                                    | Session and step-up material reject impossible remove requests before loading target credential when no live authority exists.                                                                | Current subject context plus target credential instance.                                                                                                                          | Enforce after-state survivor and recovery-authority posture, mark removed/revoked, revoke sessions/devices when policy requires it.       | Authenticated removal planning and immediate execution are live in lower-core/private Postgres/private mounted-service shape. Planning records immediate authorization or schedules a delayed removal without revoking auth state. Execution is core-owned, forbids method work, revokes the target credential, raises subject auth-state revocation, and has a commit-time guard requiring another active credential instance while rejecting remaining ordinary-plus-second-factor survivor pairs that collapse to one immediate reset authority. The mounted route is covered with exact operation-count assertions. Public mounted route rendering remains future work.                                    |
| Schedule delayed deletion or reset                                   | Session/proof cookies and weak gates reject impossible schedule requests before writes.                                                                                                       | Subject context, requested action kind, target credential or subject, cancellation rules, and notice requirements.                                                                | Create durable pending-action record, enqueue notices, define earliest execution time and expiration.                                     | Delayed credential-reset scheduling exists; authenticated delayed replacement/removal/regeneration scheduling exists; mounted subject-auth-state deletion scheduling now derives the subject from the authenticated session, requires configured step-up freshness, accepts an empty body only, generates pending-action id/timing internally, emits only coarse route response windows, and has PgBouncer-backed coverage for stale-session rejection before pending-action creation plus successful noticeful scheduling.                                                                                                                                                                                    |
| Execute pending deletion or reset                                    | Pending-action id plus deadline can reject too-early or expired execution before broader state work.                                                                                          | Pending-action record identifies subject, action, target, earliest execution time, expiration, and required prior notices.                                                        | Lock pending action and target state, enforce stale-action preconditions, execute mutation, revoke sessions/devices, audit.               | Pending credential-reset execution exists; non-reset credential-targeted execution exists; Postgres subject-auth-state deletion execution exists; mounted app-owned data lifecycle integration is Queue-backed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Cancel pending deletion or reset                                     | Session/proof cookies can reject impossible cancellation before pending-action or target mutation work.                                                                                       | Subject context plus pending-action id.                                                                                                                                           | Verify cancellation policy, close unexpired pending action, enqueue cancellation notice.                                                  | Built for authenticated credential-reset and non-reset credential-targeted pending actions; Postgres subject-auth-state deletion cancellation exists; mounted app-owned data lifecycle integration applies only to execution, not cancellation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Admin/support recovery intervention                                  | Runtime must reject unverified app claims; only a Paranoid-shaped verified intervention can reach stateful recovery work.                                                                     | Verified admin/support authority scoped to subject, credential target, action, and lifetime; configured wait/notice policy; active proof if required.                             | Audit intervention, create or execute pending action, enforce notices and revocation policy.                                              | Lower-core typed intervention model exists and lifecycle evaluation rejects wrong-scope or expired interventions. The private mounted workflow is implemented for request, approval, denial, expiry, staff authorization, notices, audit, immediate-vs-delayed lifecycle handoff, CSRF-before-storage route guarding, and coarse user-visible JSON without internal lifecycle ids. Public exposure and final product rendering remain future work.                                                                                                                                                                                                                                                             |
| Complete full authentication                                         | Active-proof continuation cookie deadline and secret can reject impossible or stolen-id completions before loading the attempt.                                                               | Active-proof continuation cookie carries attempt id plus secret; attempt records carry satisfied proof summaries and subject binding.                                             | Load attempt, validate proof-stack policy, check subject revocation, create session and optional trusted device.                          | Postgres runtime derives the attempt id from the continuation cookie and covers full-authentication completion through PgBouncer-backed tests. Missing, wrong-use, and expired continuation cookies are pinned to reject with an empty database-operation observer.                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Complete step-up                                                     | Fresh session cookie and active-proof continuation cookie deadlines can reject impossible completion before loading old session state.                                                        | Session cookie plus active-proof continuation cookie.                                                                                                                             | Load session and attempt, validate subject match and proof-stack policy, refresh step-up freshness.                                       | Postgres runtime derives the attempt id from the continuation cookie and covers step-up completion through PgBouncer-backed tests. Missing, wrong-use, and expired continuation cookies are pinned to reject with an empty database-operation observer.                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Logout and targeted revocation                                       | Missing or expired cookies can avoid unnecessary state work when no live credential can be affected.                                                                                          | Presented session or trusted-device cookie identifies target context.                                                                                                             | Load and lock target credential when needed, mark revoked, clear cookies.                                                                 | Modeled in reducer and Postgres runtime tests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Subject-wide revocation                                              | Caller must already have an authenticated subject context; no stateless material alone may revoke a subject.                                                                                  | Authenticated session context identifies the subject.                                                                                                                             | Commit subject auth-state revocation and ensure older sessions/devices cannot succeed afterward.                                          | Modeled in reducer and Postgres runtime tests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

## Fast-Fail Audit Status

This audit records the executable status of each matrix row above. The classification is
about the current live auth code, not the eventual public alpha surface. Current private
WIP route families have operation-count coverage where they exist. Future public routes or
route rewrites need their own operation-count coverage when they are built.

Classifications:

- **Fully pinned by tests**: the current executable path has named tests for its
  no-storage or bounded-storage claim, and positive auth still reaches authoritative state
  where success requires it.
- **Modeled only**: the lower contract or test-plugin shape exists, but there is no
  concrete production method/runtime path yet. No executable fast-fail guarantee is
  claimed for that row.
- **Pinned private WIP route/runtime path**: the current private runtime or mounted route
  path is implemented and has exact operation-count or no-storage tests, while final
  public rendering or post-alpha protocol work may still remain.

| Transition                                                           | Classification                                                                                 | Test evidence and remaining work                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Safe read with fresh safe-read cache                                 | Fully pinned by tests.                                                                         | `safe_read_cache_authenticates_without_commit_work`, `safe_read_cache_cannot_authenticate_state_changing_requests`, `safe_read_cache_cannot_authenticate_sensitive_requests`, and `postgres_runtime_safe_read_cache_hit_avoids_database_work` pin the bounded safe-read exception and empty database-operation observer.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Session resolution after cache miss or unsafe request                | Fully pinned by tests.                                                                         | `postgres_runtime_request_resolution_rejects_expired_passive_cookies_before_db` pins expired session-cookie rejection before DB. `postgres_runtime_executes_session_and_trusted_device_lifecycle`, `subject_wide_revocation_invalidates_loaded_session_during_request_resolution`, and `live_session_cookie_without_authoritative_record_is_cleared` pin the authoritative positive and stale-state boundaries.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Trusted-device silent revival                                        | Fully pinned by tests.                                                                         | `postgres_runtime_request_resolution_rejects_expired_passive_cookies_before_db`, `trusted_device_silent_revival_creates_session_and_rotates_device`, `trusted_device_past_silent_revival_requires_active_proof`, and `postgres_runtime_executes_session_and_trusted_device_lifecycle` pin the cookie-ceiling, silent-window, rotation, and authoritative-device checks.                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Start step-up active-proof attempt                                   | Fully pinned by tests.                                                                         | `postgres_runtime_current_session_active_proof_start_without_session_does_not_write` and `web_runtime_current_session_active_proof_start_without_session_does_not_write` pin missing-session no-write behavior. `postgres_runtime_executes_step_up_completion` and `postgres_runtime_executes_session_and_trusted_device_lifecycle` cover valid runtime-derived subject starts.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Start trusted-device active-revival proof attempt                    | Fully pinned by tests.                                                                         | `postgres_runtime_current_trusted_device_active_proof_start_without_device_does_not_write` pins missing-device no-storage behavior. `postgres_runtime_executes_session_and_trusted_device_lifecycle` covers valid runtime-derived trusted-device active-revival start.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Trusted-device active revival                                        | Fully pinned by tests.                                                                         | `postgres_runtime_completion_facades_reject_missing_continuation_before_db`, `postgres_runtime_completion_facades_reject_wrong_continuation_use_before_db`, and `postgres_runtime_completion_facades_reject_expired_continuation_before_db` pin continuation-cookie rejection before DB. `postgres_runtime_executes_session_and_trusted_device_lifecycle` pins bounded authoritative completion, session issuance, device rotation, and attempt closure.                                                                                                                                                                                                                                                                                                                                                                                     |
| Start unauthenticated active-proof attempt and issue first challenge | Fully pinned by tests for the built email OTP full-auth start path.                            | `postgres_runtime_rejects_unbound_challenge_issue_preflight_before_writes`, `postgres_runtime_rejects_unbound_challenge_issue_preflight_gate_mismatch_before_writes`, and `postgres_runtime_method_derived_email_otp_start_rejects_bad_payload_before_writes` pin pre-write rejection. `postgres_runtime_method_derived_email_otp_start_derives_dedupe_and_delivery_facts` and `mounted_auth_http_full_authentication_email_otp_route_executes_end_to_end` pin method-derived delivery facts, dedupe, duplicate-start rollback, replacement cooldown, and exact operation sequences for the mounted WIP route.                                                                                                                                                                                                                               |
| Issue out-of-band challenge on an existing attempt                   | Fully pinned by tests.                                                                         | `postgres_runtime_challenge_issue_facades_reject_missing_or_expired_continuation_before_db` pins missing/expired continuation rejection for existing-attempt challenge issue. `web_runtime_rejects_direct_out_of_band_issue_command` pins that callers cannot pass the lower direct command through the web runtime.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Resend out-of-band challenge                                         | Fully pinned by tests.                                                                         | `postgres_runtime_rejects_method_facades_until_registry_is_configured` pins missing, malformed, wrong-family, and expired challenge-cookie resend rejection with an empty database-operation observer. `resending_out_of_band_challenge_records_budget_and_queues_delivery` and `resending_out_of_band_challenge_rejects_exhausted_resend_budget` pin the authoritative resend path and budget boundary.                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Complete out-of-band challenge                                       | Fully pinned by tests.                                                                         | `web_runtime_rejects_bad_challenge_response_before_loading_state`, `web_runtime_rejects_expired_out_of_band_cookie_before_weak_gate`, `web_runtime_rejects_out_of_band_cookie_without_response_mac_before_weak_gate`, and `web_runtime_rejects_submitted_secret_for_non_out_of_band_challenge_before_loading_state` pin zero load/commit pre-state rejection. `postgres_runtime_rejects_bad_email_otp_before_subject_resolution` pins the Postgres email OTP no-storage wrong-code path, and `postgres_runtime_derives_email_otp_subject_from_method_state` pins authoritative subject resolution after the gate.                                                                                                                                                                                                                            |
| Issue message-signature challenge                                    | Fully pinned by tests for password-derived signature; future signature plugins remain modeled. | `postgres_runtime_completes_password_derived_signature_after_authoritative_recheck` pins challenge issue sealing the verifier material used later. `postgres_runtime_challenge_issue_facades_reject_missing_or_expired_continuation_before_db` pins existing-attempt missing/expired continuation no-storage rejection. SSH, wallet, and similar methods are future plugin scopes.                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Complete message-signature challenge                                 | Fully pinned by tests for password-derived signature.                                          | `postgres_runtime_rejects_wrong_password_derived_signature_before_database_work`, `postgres_runtime_rejects_invalid_password_derived_weak_gate_before_database_work`, and `postgres_runtime_rejects_reused_password_derived_weak_gate_for_different_signature_before_database_work` pin pre-DB rejection. `postgres_runtime_completes_password_derived_signature_after_authoritative_recheck` and `postgres_runtime_rejects_password_derived_signature_after_verifier_rotation` pin authoritative locked verifier/version recheck after pre-state signature success.                                                                                                                                                                                                                                                                         |
| Issue origin-bound public-key challenge                              | Modeled only.                                                                                  | `postgres_runtime_completes_origin_bound_public_key_through_method_registry` covers the generic active-method family through a test plugin. A real WebAuthn/passkey plugin, mature crate selection, and origin/RP challenge-state tests are not built.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Complete origin-bound public-key challenge                           | Modeled only.                                                                                  | `postgres_runtime_completes_origin_bound_public_key_through_method_registry` proves the lower method-registry family can carry an origin-bound proof. Concrete WebAuthn/passkey assertion parsing, origin/RP rejection before local state, and authoritative credential counter/status tests are not built.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Issue federated-identity challenge                                   | Modeled only.                                                                                  | `postgres_runtime_completes_federated_identity_through_method_registry` covers the generic federated family through a test plugin. Concrete OIDC/SAML state, nonce, redirect, issuer, audience, and mature crate tests are not built.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Complete federated-identity assertion                                | Modeled only.                                                                                  | `postgres_runtime_completes_federated_identity_through_method_registry` proves the lower family can record a federated proof. Concrete OIDC/SAML assertion validation before mapping, authoritative account-link lookup, and provider-specific tests are not built.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Direct known-subject TOTP                                            | Fully pinned by tests.                                                                         | `postgres_runtime_rejects_invalid_totp_weak_gate_before_state_load` pins invalid weak gate before DB. `postgres_runtime_completes_totp_through_known_subject_method_registry` pins wrong-code authoritative verifier lookup and proof-source provenance. `postgres_runtime_deletes_attempt_after_totp_failure_budget` pins ceremony-local budget exhaustion without account lockout.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Challenge-bound TOTP                                                 | Fully pinned by tests.                                                                         | `challenge_bound_configured_secret_bloom_filter_rejects_definite_non_matches`, `challenge_bound_configured_secret_bloom_filter_is_bound_to_context`, and `challenge_bound_configured_secret_bloom_filter_rejects_invalid_shapes` pin the primitive. `postgres_runtime_challenge_bound_totp_bloom_rejects_definite_miss_before_database_work`, `postgres_runtime_rejects_invalid_challenge_bound_totp_weak_gate_before_database_work`, `postgres_runtime_challenge_bound_totp_bloom_possible_hit_completes_authoritatively`, `postgres_runtime_challenge_bound_totp_bloom_possible_hit_rechecks_verifier_version`, and `postgres_runtime_challenge_bound_totp_bloom_has_no_false_negative_for_late_window_code` pin the runtime lane.                                                                                                         |
| Recovery code                                                        | Fully pinned by tests.                                                                         | `postgres_runtime_completes_recovery_code_through_known_subject_method_registry`, `postgres_runtime_rejects_malformed_no_session_recovery_code_before_db`, and `postgres_runtime_no_session_recovery_route_rejected_proof_does_not_issue_csrf_handoff` pin malformed/guessed/wrong-subject no-storage rejection, plausible sealed-token authoritative lookup without consumption, and mounted response indistinguishability. `postgres_runtime_authenticated_recovery_code_addition_generates_post_commit_codes`, `postgres_runtime_pending_recovery_code_regeneration_replaces_active_set_at_execution`, and `postgres_runtime_recovery_code_regeneration_rejects_missing_method_owned_set` pin generation/regeneration boundaries.                                                                                                         |
| Add credential                                                       | Pinned private WIP route/runtime path.                                                         | `postgres_runtime_authenticated_credential_addition_builds_method_work_internally`, `postgres_runtime_authenticated_credential_addition_requires_fresh_step_up_before_method_work`, `postgres_runtime_authenticated_credential_addition_rejects_same_authority_factor_collapse`, `postgres_mounted_credential_lifecycle_adds_authenticated_credential_through_private_runtime`, and `mounted_auth_http_credential_addition_route_uses_configured_method_and_csrf_guard` pin runtime-owned ids, lifecycle evidence, method work, CSRF-before-storage rejection, exact mounted route operation counts, and mounted WIP route execution. Final public rendering remains Phase 7 work.                                                                                                                                                           |
| Replace or reset credential                                          | Pinned private WIP route/runtime path.                                                         | `postgres_runtime_authenticated_credential_reset_planning_builds_lifecycle_context_internally`, `postgres_runtime_authenticated_credential_reset_planning_requires_fresh_step_up_before_lifecycle_load`, `postgres_runtime_authenticated_credential_reset_builds_method_work_internally`, `postgres_runtime_authenticated_credential_replacement_builds_method_work_internally`, `postgres_runtime_authenticated_ordinary_replacement_rejects_same_authority_factor_collapse`, `postgres_runtime_authenticated_second_factor_replacement_rejects_same_authority_factor_collapse`, `mounted_auth_http_credential_reset_route_builds_method_work_and_uses_csrf_guard`, and `mounted_auth_http_credential_replacement_route_builds_method_work_and_uses_csrf_guard` pin the current runtime and mounted WIP routes with exact operation counts. |
| Remove credential                                                    | Pinned private WIP route/runtime path.                                                         | `postgres_runtime_authenticated_credential_removal_planning_authorizes_immediate_without_revocation`, `postgres_runtime_authenticated_credential_removal_revokes_target_without_method_work`, `postgres_runtime_authenticated_second_factor_removal_rejects_ordinary_only_survivor`, `postgres_runtime_ordinary_removal_rejects_same_authority_survivor_collapse`, `postgres_runtime_authenticated_credential_removal_rejects_last_active_credential`, and `mounted_auth_http_credential_removal_route_revokes_target_and_uses_csrf_guard` pin the current removal path with exact operation counts.                                                                                                                                                                                                                                         |
| Rotate credential                                                    | Pinned private WIP route/runtime path.                                                         | `postgres_runtime_authenticated_credential_rotation_builds_method_work_internally`, `postgres_runtime_authenticated_credential_rotation_execution_requires_fresh_step_up_before_method_work`, `postgres_runtime_authenticated_rotation_rotates_real_password_derived_signature_verifier`, `postgres_runtime_authenticated_rotation_rotates_real_totp_verifier`, and `mounted_auth_http_credential_rotation_route_builds_method_work_and_uses_csrf_guard` pin the current rotation path with exact operation counts.                                                                                                                                                                                                                                                                                                                          |
| Schedule delayed deletion or reset                                   | Pinned private WIP route/runtime path.                                                         | `postgres_runtime_authenticated_credential_reset_planning_generates_pending_action_internally`, `postgres_runtime_authenticated_credential_replacement_planning_generates_pending_action_internally`, `postgres_runtime_authenticated_credential_removal_planning_generates_pending_action_internally`, `postgres_runtime_authenticated_credential_regeneration_planning_generates_pending_action_internally`, `postgres_runtime_authenticated_subject_auth_state_deletion_scheduling_derives_subject_and_policy_timing`, and `mounted_auth_http_subject_auth_state_deletion_routes_commit_only_coarse_outcomes` pin the current scheduling paths with exact operation counts.                                                                                                                                                               |
| Execute pending deletion or reset                                    | Pinned private WIP route/runtime path.                                                         | `postgres_runtime_unauthenticated_credential_reset_executes_immediate_recovery_inside_runtime`, `postgres_runtime_no_session_recovery_reset_replaces_real_password_derived_signature_verifier`, `postgres_runtime_mature_pending_subject_auth_state_deletion_closes_action_and_revokes_auth_state`, `postgres_mounted_delayed_credential_lifecycle_executes_support_scheduled_reset`, and `mounted_auth_http_delayed_credential_lifecycle_route_executes_support_scheduled_reset` pin current execution paths with exact operation counts, including deliberate mounted pre-dispatch snapshot reads where present.                                                                                                                                                                                                                           |
| Cancel pending deletion or reset                                     | Pinned private WIP route/runtime path.                                                         | `postgres_runtime_authenticated_pending_credential_reset_cancellation_closes_open_action`, `postgres_runtime_authenticated_pending_credential_reset_cancellation_requires_fresh_step_up_before_pending_load`, `postgres_runtime_authenticated_pending_credential_cancellations_reject_wrong_subject_session`, `postgres_runtime_authenticated_pending_subject_auth_state_deletion_cancellation_closes_open_action`, `postgres_runtime_authenticated_pending_subject_auth_state_deletion_cancellation_requires_fresh_step_up_before_pending_load`, and `mounted_auth_http_subject_auth_state_deletion_routes_commit_only_coarse_outcomes` pin the current cancellation paths with exact operation counts.                                                                                                                                     |
| Admin/support recovery intervention                                  | Pinned private WIP route/runtime path.                                                         | `postgres_runtime_admin_support_intervention_request_and_denial_are_candidate_owned`, `postgres_runtime_admin_support_intervention_request_rejects_subject_target_mismatch`, `postgres_runtime_admin_support_intervention_expiry_is_deadline_derived`, `postgres_runtime_admin_support_intervention_approval_enters_immediate_lifecycle_policy`, `postgres_runtime_admin_support_intervention_approval_can_schedule_delayed_lifecycle_work`, `postgres_mounted_admin_support_approval_runs_staff_authorization_before_runtime_commit`, and `mounted_auth_http_admin_support_routes_use_staff_authorization_and_coarse_outcomes` pin the private runtime and mounted WIP workflow with exact operation counts, including deliberate staff-verification snapshot reads.                                                                        |
| Complete full authentication                                         | Fully pinned by tests.                                                                         | `postgres_runtime_completion_facades_reject_missing_continuation_before_db`, `postgres_runtime_completion_facades_reject_wrong_continuation_use_before_db`, and `postgres_runtime_completion_facades_reject_expired_continuation_before_db` pin pre-DB continuation rejection. `postgres_runtime_executes_session_and_trusted_device_lifecycle` and `mounted_auth_http_full_authentication_email_otp_route_executes_end_to_end` pin authoritative proof-stack validation before session/trusted-device issuance.                                                                                                                                                                                                                                                                                                                             |
| Complete step-up                                                     | Fully pinned by tests.                                                                         | `postgres_runtime_completion_facades_reject_missing_continuation_before_db`, `postgres_runtime_completion_facades_reject_wrong_continuation_use_before_db`, and `postgres_runtime_completion_facades_reject_expired_continuation_before_db` pin pre-DB continuation rejection. `postgres_runtime_executes_step_up_completion` pins session/attempt subject matching and freshness update.                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Logout and targeted revocation                                       | Fully pinned by tests.                                                                         | `web_runtime_executes_logout_and_renders_delete_session_and_csrf_headers`, `postgres_runtime_executes_revocation_paths`, and `postgres_runtime_tripwires_replayed_previous_secrets_after_grace` pin cookie clearing, targeted revocation, and tripwire behavior.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Subject-wide revocation                                              | Fully pinned by tests.                                                                         | `subject_wide_revocation_invalidates_loaded_session_during_request_resolution`, `subject_wide_revocation_invalidates_trusted_device_during_request_resolution`, `postgres_runtime_executes_revocation_paths`, and `postgres_runtime_rejects_stale_loaded_state_commits_after_revocation` pin authoritative subject-wide revocation and stale-commit rejection.                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

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

### Recovery Code Generation And Regeneration

Recovery-code generation is a credential lifecycle transition, not a method helper an
application calls directly. A recovery-code set is one credential instance whose
individual user-visible codes are high-entropy one-time secrets. Paranoid owns code
generation, sealing, verifier storage, response materialization, notices, and lifecycle
policy.

Initial generation creates a recovery-code credential instance only through the
credential-addition lifecycle path. Regeneration uses
`CredentialLifecycleAction::Regenerate` against an existing recovery-code credential
instance. Both paths must be authorized by the same lifecycle-authority model as other
credential mutations; applications must not pass method work, recovery-authority facts,
credential ids, or "preserve sessions" flags by hand.

For each generated user-visible recovery code, Paranoid creates an opaque sealed token:

```text
recovery_code = base58(encrypt({ subject_id, random_token }))
```

Storage keeps only method-owned verifier rows for those random tokens, such as MACs bound
to the subject id, credential instance id, method label, and code id. The database must
not store plaintext recovery codes or sealed user-visible strings as bearer material.

The response may show newly generated recovery codes exactly once, and only after the
transaction that created or regenerated them commits. If commit fails, no generated code
may be released to the application or user. Generated plaintext code material is response
material, not durable auth state.

The private mounted credential-lifecycle service now projects generated recovery-code sets
from committed addition, delayed-regeneration execution, and authenticated immediate
regeneration execution into an owned route response body. That projection consumes the
mounted execution, redacts debug output, and keeps route-shaped code from borrowing
through raw runtime response material. The top-level private mounted route service uses
this projection for credential-addition and authenticated immediate-regeneration
responses; final public product rendering remains broader mounted-runtime work.

Regeneration replaces the usable recovery-code set atomically. At execution, method-owned
work must make old unused recovery codes unusable and create the new set in the same
commit as pending-action closure or immediate authorization, audit, notices, and
subject-auth-state revocation. Consumed historical codes may remain as audit/accounting
state, but they must not become usable again and must not be mixed with the new active
set.

Regeneration requires the target recovery-code credential to have existing method-owned
set state. A set with all codes consumed may still be regenerated, because historical rows
prove the credential set existed. A target credential with no recovery-code rows is
corrupt or incomplete state and must fail loudly instead of being silently repaired by
inserting a new set.

Delayed regeneration must not generate user-visible codes when the pending action is
scheduled. The pending action stores only the target credential and lifecycle action.
Fresh recovery codes are generated at execution time, after the pending action is mature
and before commit, then released only if the commit succeeds.

Authenticated regeneration planning is a lifecycle-authority transition. It either records
immediate authorization or creates a delayed `Regenerate` pending action with audit and
notice work. Planning does not build method-owned regeneration work and does not generate
user-visible recovery codes. Authenticated immediate regeneration execution is a separate
runtime-owned lane: it derives the live session and lifecycle authority inside the
transaction, rejects stale step-up before target lifecycle or method work, asks the
registered target method to build regeneration work, commits audit, notice, method work,
and subject-auth-state revocation atomically, and releases generated recovery codes only
after that commit succeeds.

Recovery-code generation and regeneration do not need brute-force fast-fail mechanisms.
The codes are high-entropy one-time secrets. The important security properties are
Paranoid-owned generation, no plaintext storage, atomic set replacement, one-time
consumption, lifecycle-authority checks, durable notices, and post-execution
subject-auth-state revocation.

### Origin-Bound Public Keys

WebAuthn and passkeys are not generic message signatures. Origin, relying-party id,
challenge, client-data hash, credential id, authenticator flags, and sign-count semantics
are intrinsic to the family.

Concrete implementations should use mature protocol crates. The runtime still owns
challenge construction, encrypted cookie state, completion sequencing, and authoritative
subject/credential mutation.

Passkey removal and replacement are credential lifecycle transitions. Applications must
not delete passkey rows or overwrite credential ids directly. The method plugin owns
WebAuthn assertion verification and method-owned state such as credential id, public key,
sign-count or backup-state metadata, but Paranoid owns lifecycle authority, pending-action
policy, notices, audit, and subject-auth-state revocation.

Removing a passkey requires lifecycle authority for `CredentialLifecycleAction::Remove`. A
live session alone is not automatically independent authority to remove the passkey that
may have created or recovered that session. The loaded lifecycle-authority graph must
decide whether the session represents an independent recovery authority. If the removal
would leave the subject without another active credential that can preserve access under
policy, the transition must be rejected or routed through the configured delayed/support
policy rather than instantly removing the last strong factor.

Replacing a passkey is two separate facts that must not collapse:

- the candidate new passkey assertion proves the browser/user controls the new
  origin-bound credential;
- lifecycle authority to replace the old passkey must come from the current subject
  context, an independent proof stack, a matured pending action, or a scoped support
  intervention.

The candidate new passkey must not authorize its own binding. Immediate replacement
supersedes the old credential and commits method-owned new-credential state in the same
transaction as audit, notices, and subject-auth-state revocation. Delayed replacement
schedules only a pending lifecycle action; candidate credential material must be created
or revalidated at execution according to the eventual WebAuthn method contract.

### Federated Identity Assertions

OIDC and SAML-style methods are app-accepted assertions from another identity authority.
They are not app-owned factors in the same way as password-derived signing, TOTP, email
OTP, or trusted devices.

Concrete implementations should use mature protocol crates. Encrypted challenge state must
bind issuer, audience, redirect target, nonce, state, and PKCE-like data where applicable.
Assertion validity can be checked before subject mapping, but account linking and session
issuance remain authoritative state work.

OIDC-linked recovery is lifecycle-authority policy over an external authority source, not
raw OAuth-style application access. A validated OIDC assertion may prove that a browser
controls one provider subject under one issuer/client/audience configuration. It does not
by itself decide which Paranoid subject may be mutated, which credential may be reset, or
whether the assertion is independent from email or another provider path.

The stable proof source for OIDC-style recovery should be derived from provider identity
facts such as configured provider id, issuer, tenant where applicable, and external
subject id. Email claims are display or policy inputs, not sufficient stable identifiers
by themselves. If policy intentionally treats a Google Workspace OIDC assertion and an
email OTP to the same Workspace-controlled mailbox as the same effective authority, both
sources must map to the same `RecoveryAuthorityId`; the proof-stack evaluator must then
reject them as non-independent where independence is required.

Linking or replacing an OIDC authority has the same two-fact shape as passkey and
identifier changes:

- the candidate OIDC assertion proves control of that external identity;
- lifecycle authority to link, replace, unlink, or use that authority for recovery comes
  from the current subject context, an independent proof stack, a delayed pending action,
  or a scoped support intervention.

The candidate OIDC assertion must not authorize its own link as a recovery authority.
Unlinking or replacing an OIDC authority must preserve configured access/recovery
requirements, send durable notices, audit the lifecycle mutation, and revoke existing
subject auth state when provider routing or recovery authority changes.

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

Current executable coverage pins this for the built weak-failure budget path. Lower-core
budget exhaustion plans only active-ceremony mutation plus continuation-cookie deletion,
with no method work, fresh secrets, or durable effects. The Postgres TOTP
budget-exhaustion path deletes only the active-proof attempt, preserves the subject
revocation cutoff, emits no new security-notification state, leaves the configured TOTP
verifier intact, and leaves the existing live session usable.

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
identifier or drain delivery budget. Live duplicate starts suppress delivery and fresh
ceremony cookies; after the configured replacement cooldown, a start may close the prior
core and method-owned challenges and issue a fresh ceremony before the old challenge TTL
expires. Those rules should bound sends and ceremonies without making the named subject
permanently or globally unable to log in.

Progressive friction means increasing the cost or ceremony burden for the current
untrusted flow, not disabling a subject, credential, or identifier. Its rules are:

- the runtime may require a stronger configured weak gate, a higher proof-of-work
  difficulty, a human challenge, a risk-adapter pass, a new ceremony, or a longer delivery
  cooldown after repeated failures;
- progression must be derived from Paranoid-owned ceremony state, challenge state, or
  privacy-preserving delivery state, not from application-provided "bad user" facts;
- before state load, invalid weak-gate evidence must remain a pure rejection and must not
  create a database write;
- after a valid continuation or challenge cookie, failure accounting may close only the
  current active-proof attempt or challenge ceremony;
- progression must be bound to the proof use, method, challenge context, and submitted
  strong-proof payload where applicable, so one solved gate cannot amortize many guesses;
- progression must never become account-level lockout, identifier-level lockout, or a
  permanent block on legitimate recovery.

Out-of-band delivery controls must bound harassment and provider spend without becoming
identity enumeration or account denial. The structural policy is:

- challenge issue and resend may enqueue delivery only from committed auth transitions;
- delivery dedupe keys must be runtime or method generated from canonical,
  privacy-preserving handles, not raw email addresses, phone numbers, OTPs, or app-owned
  strings;
- delivery cooldown and resend budget state is scoped to an active ceremony, verified
  recipient binding, or other privacy-preserving delivery bucket, not to a globally locked
  subject or identifier;
- repeated resend should continue the same open ceremony when possible instead of creating
  unbounded new active-proof attempts or proof shapes;
- user-facing responses must not reveal whether a recipient, subject, method, or
  identifier exists;
- idempotency keys for external delivery must be generated or validated by Paranoid and
  committed with the durable delivery command;
- exhausting a delivery budget may close the ceremony or require a fresh weak gate, but
  must not make the named subject or identifier unable to authenticate through other valid
  ceremonies;
- exact cooldown durations, resend counts, and friction thresholds are configurable policy
  values, but the no-lockout, no-enumeration, durable-effect, and
  privacy-preserving-keying rules are fixed invariants.

Current executable coverage pins the built open-dedupe path at the Postgres runtime
boundary. A live out-of-band dedupe bucket rejects duplicate challenge issue without
persisting a new attempt or delivery command. Once the original challenge expires, the
same opaque recipient bucket can issue a replacement challenge, close the stale open
dedupe row, and complete full authentication. Resend budgets and delivery idempotency are
covered separately. The mounted full-authentication request vocabulary, parser boundary,
route advertisement, and email OTP end-to-end route execution are covered. The private
Postgres runtime has method-registry start-derivation coverage proving bad email OTP start
payloads reject before DB work and same-recipient starts reuse the method-derived live
dedupe bucket without accepting caller-owned delivery facts. The mounted
full-authentication route now also maps the live duplicate-dedupe start case to the same
accepted public response body a fresh start at that time would render, emits no response
cookies, rolls back fresh attempt work, and enqueues no additional core or method
delivery. Final cooldown policy and the broader cross-browser duplicate-start product
shape remain design and implementation work.

Weak gates are configurable method/policy components. Paranoid provides a native
Hashcash-style proof-of-work backend verifier because it is app-owned, providerless, and
fits the fast-fail philosophy. Paranoid should also support human/risk gates through clear
runtime-owned integrations: Cloudflare Turnstile, Google reCAPTCHA, self-hosted CAPTCHA,
or an application risk engine can be adapters that verify provider evidence and mint a
Paranoid-owned `VerifiedWeakProofGateBeforeStateLoad`-style fact. Applications choose the
gate policy in config; they should not hand the core a naked "captcha passed" boolean.

The lower-core adapter contract for human and risk gates is intentionally narrow. A
configured adapter receives the opaque response payload plus Paranoid-derived context: the
proof being protected and either the exact strong-proof binding digest or the
challenge-issue proof-use context. The adapter returns only verification success or
failure. It cannot return a subject id, a satisfied proof, lifecycle authority, method
work, or any other positive auth fact. Native Hashcash remains first-party proof-of-work;
adapter callbacks cannot masquerade as that gate family.

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

Core durable effect records are handed to Paranoid Queue by a private auth dispatcher. The
dispatcher locks undispatched committed effect rows, enqueues the corresponding Queue job,
and records a dispatch marker in the same transaction. The dispatch marker is permanent
auth delivery state: it prevents a completed Queue job from making the same auth effect
eligible for enqueue again. If Queue enqueue fails, the dispatch transaction rolls back
and the original committed effect row remains recoverable on a later dispatch pass.

Core auth Queue delivery handlers are also private auth runtime machinery. They register
exactly the Queue tasks for committed out-of-band messages and committed security
notifications. The handlers decode the Queue JSON payload into typed auth delivery
requests, validate the committed payload shape, and reject malformed stored jobs as
permanent Queue task failures before calling an external delivery integration.

Delivery integrations receive committed, non-secret delivery facts only: durable effect
id, stable effect idempotency key, Queue job id, retry counters, recipient or subject
handle, method label, challenge id or notification kind, expiry, and the method/core
delivery idempotency key where applicable. They do not receive auth internals, verified
proof facts, pending-action records, lifecycle authority facts, or mutation work. A
delivery callback must classify its own provider outcome as success, retryable failure, or
permanent failure. Queue owns claim, retry scheduling, stale running-job recovery,
dead-lettering, and worker outcome summaries.

This bridge covers core durable effects: out-of-band message commands and security
notification commands from session, trusted-device, lifecycle, and admin/support
transitions.

Method-owned durable effects are handed to Queue through the registered method plugin that
owns the corresponding method tables and commit work. The registry exposes private
dispatch and worker-registration hooks; applications do not enqueue method effects, pass
method work, or construct delivery facts. The first concrete method-owned bridge is email
OTP delivery: email OTP commits an encrypted delivery command row inside the auth
transition, a registry dispatch pass locks undispatched method rows and records the Queue
job id on the method row in the same transaction as enqueue, and the Queue handler rejects
queued JSON unless it points back to that committed dispatched row. The handler decrypts
the response secret only after Queue claims the job, then calls a typed email OTP delivery
callback with committed delivery facts.

The private WIP mounted durable-effect worker service now composes the core and
method-owned delivery bridges into one operator-facing auth delivery boundary. It builds
one Queue task registry containing the core auth handlers plus every registered method
handler, dispatches available committed core and method durable effects in one
transaction-owned pass, exposes Queue worker pressure and orphaned-task visibility for the
mounted auth delivery registry, and delegates stale running-job recovery to Queue's normal
reclaim path. Applications provide delivery callbacks, but they do not see auth internals,
construct Queue payloads, choose method work, or run separate core-vs-method delivery
protocols. The private mounted runtime config now owns those delivery integrations, so
operator-shaped code builds the worker service from the mounted runtime instead of passing
out-of-band delivery, security-notification, or subject-data callbacks ad hoc at each
worker construction site.

The mounted worker also delivers committed application subject data lifecycle requests
created by subject-auth-state deletion. These requests are not auth proofs and not auth
mutation authority. They are a recoverable integration point that lets app-owned subject
data deletion or disabling compose with auth-owned delayed deletion without letting the
application participate in auth commit ordering.

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

The current private WIP public-shaped configuration root is `PostgresAuthSystemConfig`. It
owns the DB bootstrap config, credential secret keyset, core auth config, web transport,
weak-gate verifier, mount path, durable-effect integrations, first-party method setup, and
mounted route setup before producing a bootstrapped `PostgresAuthSystem`.
`PostgresAuthBootstrap` remains the lower implementation detail used to build stores,
method plugins, and schema state from that single config. Applications should not need to
coordinate a separate auth bootstrap object and mounted route config by convention.

The first private mounted runtime facade now wraps the bootstrapped Postgres web runtime
with mounted-route and operator configuration. The WIP mounted system config owns
first-party method setup for mounted routes that depend on those methods, including email
OTP full authentication and recovery-code to password-derived-signature no-session
recovery. Bootstrap consumes that setup to register the actual Postgres method plugins
before schema migration and runtime construction. The mounted config also owns the
configured no-session credential recovery flow and durable-effect worker integrations. The
mounted runtime construction validates registered method capabilities against the route
families it advertises: full-authentication out-of-band challenge work, no-session
recovery credential proof work, credential creation, credential reset, credential
replacement, credential regeneration, credential rotation, delayed credential lifecycle
method work, and out-of-band identifier-change candidate binding work must be backed by
plugins that explicitly declare those capabilities. The mounted system must not accept a
route family merely because an unrelated method registry exists. The mounted runtime
service bundle now produces one public-shaped mounted HTTP surface for a chosen mount
path. That surface exposes the route manifest, framework-neutral HTTP route service,
combined protected-route layer, and combined protected application-subject mapping layer,
while the bundle separately exposes the configured durable-effect worker for operator
code. The protected-route layer is the app route boundary. It is constructed from a
Paranoid-owned protected-route policy whose named constructors pair the request kind with
the required auth posture. The layer resolves mounted auth state, enforces
authenticated-subject or fresh-step-up requirements, inserts the Paranoid-owned request
state for downstream handlers, and only then calls the app service. When applications need
app-owned subject context, the mounted surface also has a combined protected
application-subject mapping layer that consumes the same protected-route policy, performs
the same auth resolution and requirement enforcement, and only then calls the application
mapper. The mapper receives only Paranoid-owned authenticated subject/session facts and
cannot create auth state, decide proof sufficiency, enqueue notices, mutate credentials,
or set cookies. The lower request-resolution, route-requirement, and unprotected
subject-mapping layers remain isolated internal/test composition pieces; applications
should not have to stack them correctly or pair request kind with auth requirement by
convention. Lower credential lifecycle, subject lifecycle, admin/support, and no-session
recovery ceremony services remain internal machinery instead of advertised bundle
surfaces. The mounted auth route service owns an application mount path, strips it from
incoming request paths, dispatches configured no-session recovery endpoints by method and
relative path, and returns typed auth route responses without exposing the lower recovery
route service to application-shaped code. Unknown mounted routes reject before auth
storage work. The mounted surface now also has a private application subject mapping
boundary: after Paranoid request resolution has authenticated a subject, a Tower layer can
call an app-owned mapper with Paranoid-owned subject/session facts and insert app-owned
subject context into request extensions. That mapper is request integration only. It does
not grant authentication, decide proof sufficiency, mutate auth state, enqueue notices,
set cookies, or participate in revocation policy. Endpoint-shaped code should not pass
proof method config, reset target config, lower route requests, lifecycle authority,
method work, delivery integrations, subject-mapping results as auth facts, or revocation
choices at each call site. The bootstrap facade can now migrate auth schema and return
this mounted runtime directly after DB foundation bootstrap.

This is not the final public mounted auth configuration. The later facade still needs to
wrap route registration, middleware/layer construction, CSRF policy, durable-effect
integrations, lifecycle policy, proof policy, method policy, public route requirement
configuration, final application subject mapping configuration, and application hooks into
the intended one-configuration product surface.

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

The current audit-event coverage matrix is:

| Event kind                                                          | Security transition                                            | Primary context                                      |
| ------------------------------------------------------------------- | -------------------------------------------------------------- | ---------------------------------------------------- |
| `SessionCreated`                                                    | Session issuance after full auth or trusted-device revival     | subject, session, optional trusted-device credential |
| `SessionRefreshed`                                                  | Session refresh inside the configured refresh window           | subject, session                                     |
| `TrustedDeviceSilentRevival`                                        | Trusted-device passive session revival                         | subject, session, trusted-device credential          |
| `TrustedDeviceActiveProofRevival`                                   | Trusted-device revival after active proof                      | subject, session, trusted-device credential, attempt |
| `TrustedDeviceCreated`                                              | Trusted-device credential creation                             | subject, session, trusted-device credential          |
| `TrustedDeviceRotated`                                              | Trusted-device credential rotation                             | subject, trusted-device credential                   |
| `StepUpCompleted`                                                   | Step-up freshness completion                                   | subject, session, attempt                            |
| `CredentialMismatch`                                                | Live credential presented an unacceptable secret               | subject if known, session or trusted-device          |
| `SessionRevoked`                                                    | Session logout, targeted revocation, or tripwire               | subject if known, session                            |
| `TrustedDeviceRevoked`                                              | Trusted-device targeted revocation or tripwire                 | subject if known, trusted-device credential          |
| `SubjectAuthStateRevoked`                                           | Subject-wide auth-state cutoff changed                         | subject                                              |
| `ActiveProofAttemptStarted`                                         | Active-proof ceremony started                                  | subject when bound, attempt                          |
| `ActiveProofMethodChallengeIssued`                                  | Non-out-of-band active-method challenge issued                 | subject when bound, attempt, challenge               |
| `OutOfBandChallengeIssued`                                          | Out-of-band challenge issued                                   | subject when bound, attempt, challenge               |
| `OutOfBandChallengeResent`                                          | Out-of-band challenge delivery resent                          | subject when bound, attempt, challenge               |
| `ActiveProofFailed`                                                 | Active proof submission failed after valid ceremony material   | subject when bound, attempt, challenge when present  |
| `ActiveProofSucceeded`                                              | Active proof submission succeeded authoritatively              | subject, attempt, challenge when present             |
| `ActiveProofAttemptClosed`                                          | Active-proof attempt consumed by successful transition         | subject, attempt                                     |
| `ActiveProofAttemptDeletedAfterWeakProofFailures`                   | Ceremony-local weak-failure budget exhausted                   | subject when bound, attempt                          |
| `CredentialResetAuthorized`                                         | Immediate credential reset authorized                          | subject, target credential                           |
| `CredentialResetPendingActionScheduled`                             | Delayed credential reset scheduled                             | subject, target credential                           |
| `CredentialResetExecuted`                                           | Immediate or matured credential reset executed                 | subject, target credential                           |
| `CredentialResetPendingActionCancelled`                             | Delayed credential reset cancelled                             | subject, target credential                           |
| `CredentialAdded`                                                   | Credential addition executed                                   | subject, new credential                              |
| `CredentialReplacementAuthorized`                                   | Immediate credential replacement authorized                    | subject, target credential                           |
| `CredentialReplacementPendingActionScheduled`                       | Delayed credential replacement scheduled                       | subject, target credential                           |
| `CredentialReplacementExecuted`                                     | Immediate or matured credential replacement executed           | subject, target and successor credential             |
| `CredentialReplacementPendingActionCancelled`                       | Delayed credential replacement cancelled                       | subject, target credential                           |
| `CredentialRemovalAuthorized`                                       | Immediate credential removal authorized                        | subject, target credential                           |
| `CredentialRemovalPendingActionScheduled`                           | Delayed credential removal scheduled                           | subject, target credential                           |
| `CredentialRemovalExecuted`                                         | Immediate or matured credential removal executed               | subject, target credential                           |
| `CredentialRemovalPendingActionCancelled`                           | Delayed credential removal cancelled                           | subject, target credential                           |
| `CredentialRegenerationAuthorized`                                  | Immediate credential-set regeneration authorized               | subject, target credential                           |
| `CredentialRegenerationPendingActionScheduled`                      | Delayed credential-set regeneration scheduled                  | subject, target credential                           |
| `CredentialRegenerationExecuted`                                    | Immediate or matured credential-set regeneration executed      | subject, target credential                           |
| `CredentialRegenerationPendingActionCancelled`                      | Delayed credential-set regeneration cancelled                  | subject, target credential                           |
| `CredentialRotated`                                                 | Credential verifier or secret rotation executed                | subject, target credential                           |
| `AdminSupportInterventionRequested`                                 | Support/admin intervention candidate requested                 | subject, target credential                           |
| `AdminSupportInterventionApproved`                                  | Support/admin intervention candidate approved                  | subject, target credential                           |
| `AdminSupportInterventionDenied`                                    | Support/admin intervention candidate denied                    | subject, target credential                           |
| `AdminSupportInterventionExpired`                                   | Support/admin intervention candidate expired                   | subject, target credential                           |
| `AdminSupportCredentialLifecycleInterventionAuthorized`             | Support/admin intervention authorized immediate lifecycle work | subject, target credential                           |
| `AdminSupportCredentialLifecycleInterventionPendingActionScheduled` | Support/admin intervention scheduled delayed lifecycle work    | subject, target credential                           |
| `SubjectAuthStateDeletionPendingActionScheduled`                    | Delayed subject-auth-state deletion scheduled                  | subject                                              |
| `SubjectAuthStateDeletionExecuted`                                  | Matured subject-auth-state deletion executed                   | subject                                              |
| `SubjectAuthStateDeletionPendingActionCancelled`                    | Delayed subject-auth-state deletion cancelled                  | subject                                              |
| `OutOfBandIdentifierChangeCandidateBindingReserved`                 | Candidate out-of-band identifier proof reserved                | subject, attempt, challenge, candidate source        |
| `OutOfBandIdentifierChangePendingActionScheduled`                   | Delayed out-of-band identifier change scheduled                | subject, current and candidate source                |
| `OutOfBandIdentifierChangePendingActionCancelled`                   | Delayed out-of-band identifier change cancelled                | subject, current and candidate source                |
| `OutOfBandIdentifierChanged`                                        | Out-of-band identifier binding changed                         | subject, current and candidate source                |

Pre-runtime rejections are not lifecycle audit events. Missing cookies, malformed cookies,
expired cookie ceilings, missing CSRF, malformed bodies, route misses, safe-read cache
hits, invalid weak-gate evidence before state load, and stateless fast-fail definite
misses must not append audit rows merely as request telemetry. Once a request presents
enough valid Paranoid-owned ceremony material to enter authoritative state, failure and
replay outcomes use the event kinds above when the transition is security-significant.

## Privacy And Boundaries

Public identifier flows must be indistinguishable from outside observers. User-facing
responses should not reveal whether an email, account, method, or identifier exists.

Auth core should not know application identity shape such as organizations, accounts as
emails, resource ownership, or route authorization. It should operate on subject IDs and
proof semantics. Applications decide authorization.

`SubjectId` is an opaque Paranoid auth-principal handle. Paranoid may persist, compare,
lock, revoke, audit, and route auth lifecycle state by subject id, but it must not parse a
subject id as an email, username, tenant, organization, billing account, resource owner,
route authorization target, or application account shape. Applications can map Paranoid
subjects to those concepts outside auth.

Trusted-device display labels are display metadata only. They may contain an adapter
summary such as a browser or user-agent label, but auth must not treat them as proof,
identity, policy authority, revocation scope, rate-limit key, or credential source.

IP addresses are infrastructure and abuse-control inputs, not auth-core identity signals.
Edge rate limits, risk adapters, fraud systems, or operator logs may use IP addresses
outside the core auth state machine. Positive auth decisions, credential lifecycle
authority, proof-source provenance, and subject identity must not require or derive from
IP address fields.

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
- WebAuthn/passkey, OIDC, or SAML implementations.
- Complete public credential lifecycle and recovery policy layer, including remaining
  concrete method lifecycle implementations beyond the current password-derived, TOTP, and
  recovery-code generation/regeneration paths, public no-session recovery ceremonies,
  public mounted credential/deletion routes, and public admin/support intervention.
- Full audit coverage matrix.
- Realistic adversarial application-lifecycle test suite through the mounted public
  runtime.
- Public documentation.
