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
   proof use, deadline, and the fresh secret.
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
- policy evaluation rejects proof stacks whose effective recovery authorities overlap when
  independence is required;
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

## Fast-Fail Transition Matrix

This matrix is the design checklist for every auth transition. The goal is not merely to
use fast-fail where it falls out naturally. The goal is to actively search for safe
protocol shapes where impossible or abusive requests can be rejected before authoritative
storage work.

| Transition                                                           | Pre-state rejection gate                                                                                                                                 | Sealed or presented state                                                                                                             | Authoritative work after gate                                                                                                             | Current live shape                                                                                                                                 |
| -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Safe read with fresh safe-read cache                                 | Encrypted session cookie deadline rejects expired cache without DB.                                                                                      | Session cookie carries session id, secret, hard session ceiling, and bounded safe-read deadline.                                      | None for accepted safe reads; state-changing and sensitive requests still load state.                                                     | Modeled and covered by request-resolution/load-contract tests.                                                                                     |
| Session resolution after cache miss or unsafe request                | Cookie expiry ceilings reject impossible sessions before session lookup.                                                                                 | Session cookie carries id and secret; storage keeps MACs and version state.                                                           | Load session, classify secret, check revocation, refresh window, step-up freshness, and subject-wide revocation.                          | Modeled in reducer, Postgres runtime, and request-resolution tests.                                                                                |
| Trusted-device silent revival                                        | Trusted-device cookie expiry and silent-revival deadline reject impossible passive revival before DB.                                                    | Trusted-device cookie carries credential id, secret, hard credential ceiling, and silent-revival ceiling.                             | Load credential, classify secret, check revocation, create session, rotate device credential.                                             | Modeled in reducer, Postgres runtime, and lifecycle tests.                                                                                         |
| Start step-up active-proof attempt                                   | Session cookie expiry rejects impossible step-up starts before DB.                                                                                       | Session cookie supplies the current subject/session context; caller supplies no subject id.                                           | Load session and subject revocation, validate session secret, create subject-bound attempt and continuation credential.                   | Runtime has current-session start facades; generic and Postgres tests prove missing sessions do not write and valid starts derive subject.         |
| Start trusted-device active-revival proof attempt                    | Trusted-device cookie expiry rejects impossible active-revival starts before DB.                                                                         | Trusted-device cookie supplies the subject/device context; caller supplies no subject id.                                             | Load device credential and subject revocation, validate device secret, create subject-bound attempt and continuation credential.          | Postgres lifecycle coverage starts active revival from the validated trusted-device cookie rather than a caller-supplied subject.                  |
| Trusted-device active revival                                        | Trusted-device cookie expiry and active-proof continuation cookie deadline/secret can reject impossible revival before DB.                               | Trusted-device cookie supplies known subject/device context; active-proof continuation cookie supplies attempt id plus secret.        | Validate device record and active-proof attempt, then issue a session and rotate device credential after proof-stack policy passes.       | Postgres runtime derives the attempt id from the continuation cookie and covers active revival through PgBouncer-backed tests.                     |
| Start unauthenticated active-proof attempt and issue first challenge | Runtime-owned weak gate can reject write-amplifying challenge starts before attempt/challenge writes.                                                    | Challenge issue request names intended proof use and method; no app-supplied proof verification facts are accepted.                   | Commit attempt start and challenge issue atomically, including continuation credential, method work, and durable delivery command.        | Postgres runtime has fused start-and-issue paths with preflight verification and continuation-cookie response materialization.                     |
| Issue out-of-band challenge on an existing attempt                   | Active-proof continuation cookie deadline/secret rejects impossible challenge issue before attempt load; no caller may preassemble the fast-fail cookie. | Continuation cookie carries attempt id plus secret; encrypted challenge cookie carries challenge id, proof summary, nonce, and MAC.   | Load attempt and subject revocation, enforce dedupe/open-attempt preconditions, store challenge, enqueue delivery.                        | Runtime derives the attempt id from the continuation cookie; Postgres method registry supplies generated response-secret material and method work. |
| Resend out-of-band challenge                                         | Encrypted challenge cookie must validate as an unexpired out-of-band ceremony before any DB load.                                                        | Same challenge cookie identifies the existing attempt and challenge; caller supplies only a fresh delivery idempotency key.           | Load attempt/challenge, enforce open challenge and resend budget, append delivery work.                                                   | Postgres runtime validates cookie before loading state and obtains method work from the registry.                                                  |
| Complete out-of-band challenge                                       | Wrong submitted response rejects by MAC from the encrypted challenge cookie before any DB load.                                                          | Encrypted cookie carries response MAC and challenge context; submitted response is secret material.                                   | Load attempt/challenge and subject revocation, resolve subject through method state, close challenge, consume method state, record proof. | Postgres runtime verifies MAC first, then resolves subject and method work through the registry inside the post-gate transaction.                  |
| Issue message-signature challenge                                    | Runtime-issued nonce and method-sealed verifier/context must be generated during challenge issue; any necessary lookup belongs here, not on completion.  | Encrypted challenge cookie carries nonce and method state such as canonical-message hash or sealed verifier material.                 | Store any method challenge state only through method commit work if needed.                                                               | Runtime supports active-method challenge issue; concrete password-derived signature plugin is not built.                                           |
| Complete message-signature challenge                                 | Signature over the bound challenge should reject before DB when verifier material was sealed at issue time.                                              | Encrypted cookie carries proof summary, nonce, deadline, and method challenge state.                                                  | After signature success, load attempt/challenge and authoritative verifier/version state before accepting proof.                          | Test plugins cover pre-state proof verification plus optional authoritative confirmation; first-party signature methods are not built.             |
| Issue origin-bound public-key challenge                              | Runtime-issued challenge, origin/RP context, and credential lookup context are sealed before completion.                                                 | Encrypted cookie carries nonce, origin/RP binding, credential/challenge state, and deadline.                                          | Authoritative credential state must still validate credential status, subject mapping, and replay/sign-count rules.                       | Contract and test-plugin paths exist; mature WebAuthn/passkey plugin is not built.                                                                 |
| Complete origin-bound public-key challenge                           | Assertion structure, origin/RP binding, and signed challenge can reject before DB when sealed challenge state is sufficient.                             | Encrypted cookie carries proof identity and method challenge state.                                                                   | Load attempt/challenge and authoritative credential state before accepting proof or mutating counters.                                    | Test-plugin paths cover the family shape; concrete WebAuthn/passkey implementation is not built.                                                   |
| Issue federated-identity challenge                                   | Runtime-generated state/nonce/redirect binding rejects mismatched callbacks before subject mapping.                                                      | Encrypted state cookie carries issuer, audience/client, redirect binding, nonce, state, deadline, and provider context.               | Authoritative issuer config, external subject mapping, and account-link policy still gate success.                                        | Contract and test-plugin paths exist; concrete OIDC/SAML implementation is not built.                                                              |
| Complete federated-identity assertion                                | Invalid state, nonce, issuer, audience, or assertion signature can reject before local account mapping.                                                  | Encrypted state cookie binds the callback to the initiated ceremony.                                                                  | Load attempt/challenge and authoritative mapping/linking state before accepting proof.                                                    | Test-plugin paths cover the family shape; concrete OIDC/SAML implementation is not built.                                                          |
| Direct known-subject TOTP                                            | Weak gate rejects before DB; direct code verification cannot reject wrong TOTP before fetching the subject verifier.                                     | Existing session, trusted device, or prior proof supplies the subject-bound attempt.                                                  | Load attempt and subject verifier, verify code, record success or weak failure.                                                           | Postgres TOTP plugin implements direct known-subject verification; no Bloom challenge lane is wired.                                               |
| Challenge-bound TOTP                                                 | Encrypted challenge cookie plus Bloom filter can reject definite non-matches before DB; weak gate must also pass before state load.                      | Encrypted cookie carries TOTP challenge context and Bloom bitset for the acceptable human window.                                     | Possible Bloom hits still load attempt, subject revocation, and authoritative verifier/replay state.                                      | Bloom primitive and adapter contract exist; runtime/plugin lane is not yet implemented.                                                            |
| Recovery code                                                        | Shape validation and future code-id/prefix gates should reject malformed or impossible codes before expensive lookup.                                    | Existing subject-bound attempt plus submitted one-time secret; future shape may include non-secret lookup prefix.                     | Lookup locked unused code, verify MAC, consume atomically with proof success.                                                             | Postgres recovery-code plugin consumes atomically; stronger pre-lookup fast-fail shape is not built.                                               |
| Add credential                                                       | Existing session, step-up freshness, active-proof continuation, and challenge cookies reject impossible add requests before target credential work.      | Current session plus active proof stack identify subject and proposed credential context.                                             | Evaluate lifecycle policy, verify proof independence when required, create pending or active credential, enqueue notices.                 | Not built; lower core must preserve credential-instance ids and lifecycle metadata.                                                                |
| Replace or reset credential                                          | Existing session/trusted-device/proof cookies and weak gates reject impossible reset ceremonies before target credential lookup where possible.          | Active proof stack plus target credential context.                                                                                    | Evaluate dependency graph, reject collapsed factors, enforce wait/admin/recovery-code rules, replace credential atomically.               | Not built; `RecoverOrReplaceCredential` is only scaffolding.                                                                                       |
| Remove credential                                                    | Session and step-up material reject impossible remove requests before loading target credential when no live authority exists.                           | Current subject context plus target credential instance.                                                                              | Enforce last-credential and independence policy, mark removed/revoked, revoke sessions/devices when policy requires it.                   | Not built.                                                                                                                                         |
| Schedule delayed deletion or reset                                   | Session/proof cookies and weak gates reject impossible schedule requests before writes.                                                                  | Subject context, requested action kind, target credential or subject, cancellation rules, and notice requirements.                    | Create durable pending-action record, enqueue notices, define earliest execution time and expiration.                                     | Not built.                                                                                                                                         |
| Execute pending deletion or reset                                    | Pending-action id plus deadline can reject too-early or expired execution before broader state work.                                                     | Pending-action record identifies subject, action, target, earliest execution time, expiration, and required prior notices.            | Lock pending action and target state, enforce stale-action preconditions, execute mutation, revoke sessions/devices, audit.               | Not built.                                                                                                                                         |
| Cancel pending deletion or reset                                     | Session/proof cookies and pending-action deadline can reject impossible cancellation before target mutation work.                                        | Subject context plus pending-action id.                                                                                               | Verify cancellation policy, close pending action, enqueue cancellation notice.                                                            | Not built.                                                                                                                                         |
| Admin/support recovery intervention                                  | Runtime must reject unverified app claims; only a Paranoid-shaped verified intervention can reach stateful recovery work.                                | Verified admin/support authority, subject/credential target, configured wait/notice policy, and active proof if required.             | Audit intervention, create or execute pending action, enforce notices and revocation policy.                                              | Not built; must not become an app-owned side-door mutation.                                                                                        |
| Complete full authentication                                         | Active-proof continuation cookie deadline and secret can reject impossible or stolen-id completions before loading the attempt.                          | Active-proof continuation cookie carries attempt id plus secret; attempt records carry satisfied proof summaries and subject binding. | Load attempt, validate proof-stack policy, check subject revocation, create session and optional trusted device.                          | Postgres runtime derives the attempt id from the continuation cookie and covers full-authentication completion through PgBouncer-backed tests.     |
| Complete step-up                                                     | Fresh session cookie and active-proof continuation cookie deadlines can reject impossible completion before loading old session state.                   | Session cookie plus active-proof continuation cookie.                                                                                 | Load session and attempt, validate subject match and proof-stack policy, refresh step-up freshness.                                       | Postgres runtime derives the attempt id from the continuation cookie and covers step-up completion through PgBouncer-backed tests.                 |
| Logout and targeted revocation                                       | Missing or expired cookies can avoid unnecessary state work when no live credential can be affected.                                                     | Presented session or trusted-device cookie identifies target context.                                                                 | Load and lock target credential when needed, mark revoked, clear cookies.                                                                 | Modeled in reducer and Postgres runtime tests.                                                                                                     |
| Subject-wide revocation                                              | Caller must already have an authenticated subject context; no stateless material alone may revoke a subject.                                             | Authenticated session context identifies the subject.                                                                                 | Commit subject auth-state revocation and ensure older sessions/devices cannot succeed afterward.                                          | Modeled in reducer and Postgres runtime tests.                                                                                                     |

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
   gate if the method is online-guessable, and checks the submitted signature against the
   sealed verifier before any completion-time DB hit.
4. Wrong password-derived signatures reject before DB.
5. Signature success still requires authoritative state before granting access or mutating
   durable auth state.

The branch in the raw notes where `/login/verify` reads the current public key before
signature verification is only one older sketch. It is not the best current design if the
challenge-issue step already loaded and sealed the verifier.

For password-derived signatures, the weak-proof gate must be bound to the signature or
signed payload. A solved gate must not be reusable across password guesses.

### Shared-Secret OTP

TOTP and similar configured secrets are known-subject proofs. Direct TOTP cannot identify
a subject from nothing. It must have subject context from an existing session, trusted
device, or prior active proof.

The direct known-subject lane requires a weak-proof gate before DB work. That is the
conventional path, but it is not the only Paranoid-shaped path.

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

### Recovery Codes

Recovery codes are high-entropy one-time proofs. Success requires method-owned commit work
that atomically consumes the code. Failure must not consume anything.

The future public shape should likely include a statelessly checkable prefix or code id so
malformed or impossible submissions can fail before expensive lookup work.

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
  failures;
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

Weak gates are configurable method/policy components. Paranoid should provide a native
Hashcash-style proof-of-work gate because it is app-owned, providerless, and fits the
fast-fail philosophy. Paranoid should also support human/risk gates through clear
runtime-owned integrations: Cloudflare Turnstile, Google reCAPTCHA, self-hosted CAPTCHA,
or an application risk engine can be adapters that verify provider evidence and mint a
Paranoid-owned `VerifiedWeakProofGateBeforeStateLoad`-style fact. Applications choose the
gate policy in config; they should not hand the core a naked "captcha passed" boolean.

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

The auth code is WIP private implementation behind the `auth` feature. It is not ready as
public API.

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
- Credential lifecycle and recovery policy layer, including factor-independence analysis,
  delayed actions, credential reset/replacement, and admin/support intervention.
- Full audit coverage matrix.
- Realistic adversarial application-lifecycle test suite through the mounted public
  runtime.
- Public documentation.
