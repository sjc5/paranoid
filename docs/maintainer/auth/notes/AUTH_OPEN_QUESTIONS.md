# Auth Open Questions

This document tracks unresolved auth design questions only. Resolved decisions belong in
`AUTH_DESIGN.md`. Ordered execution belongs in `AUTH_ROADMAP.md`.

If a question requires maintainer judgment, do not decide it silently. Ask the maintainer
before implementing work that depends on that answer.

## Questions That Need Maintainer Input

These are product, scope, or policy choices where the code can inform the decision but
should not make it unilaterally.

- Are deterministic email OTPs part of auth v1, a separate helper, or out of scope?
- Are SMS OTP and postal out-of-band delivery first-party scopes, adapter-only scopes, or
  postponed?
- Should the generic `AuthWebRuntime` become production substrate, or remain an internal
  model/test scaffold once the Postgres runtime is complete?
- What is the exact public mounted API shape for alpha?
    - one configuration object;
    - middleware/route registration;
    - app subject-mapping hooks;
    - durable delivery callbacks;
    - lifecycle/recovery policy config;
    - CSRF/cookie behavior owned by Paranoid.

## Questions That Need Technical Design

These do not need an immediate maintainer answer unless the design exposes a real
tradeoff. They need a concrete design before implementation continues downstream.

- How do lifecycle action decisions commit into concrete credential replacement,
  regeneration, pending-action execution, and pending-action cancellation transitions?
  Credential reset planning, execution, and authenticated pending-action cancellation
  boundaries are defined. Lower-core non-reset pending execution/cancellation now exists
  for credential-targeted replacement, removal, and regeneration, including method-work
  requirements, target credential state changes, action-specific notices, and optional
  subject auth-state revocation. Concrete first-party reset payload construction and
  replacement/regeneration scheduling are not built. Postgres runtime facades now execute
  matured non-reset credential-targeted pending actions and authenticated cancellation
  without accepting caller-provided pending records, authority facts, or method work.
  Shared pending-action semantics now distinguish credential-targeted reset, replacement,
  removal, and regeneration from subject-targeted deletion. The Postgres runtime has
  authenticated and unauthenticated reset planning facades, authenticated and
  matured-pending reset execution facades, and an authenticated pending-reset cancellation
  facade that constructs lifecycle authority, method work, or stale-action guards
  internally for the current reset boundary. Reset pending-action expiry is
  deadline-derived, and quiet cleanup closes expired open reset actions before replacement
  scheduling without a user-visible cancellation notice.
- What are the pending-action records for long waits?
    - scheduled subject/account deletion;
    - delayed second-factor reset;
    - delayed credential replacement;
    - cancellation conditions;
    - expiration;
    - atomic execution preconditions. Credential-targeted non-reset lower-core execution
      and Postgres runtime execution/cancellation facades are defined for replacement,
      removal, and regeneration, but the concrete subject-targeted storage record is not.
- What default and minimum delay policies should Paranoid provide for email-only password
  reset, second-factor reset, and destructive account deletion?
- What is the concrete Paranoid-shaped admin/support recovery intervention?
- Which lifecycle mutations require immediate subject-wide revocation, which require
  step-up freshness, and which require delayed execution?
- What is the native Hashcash-style proof-of-work contract?
- How is proof-of-work evidence bound to the proof attempt so one solved gate cannot be
  reused across many password or TOTP guesses?
- What is the adapter shape for human/risk gates such as Turnstile, reCAPTCHA, self-hosted
  CAPTCHA, or application risk engines?
- What are the progressive-friction rules and ceremony-scoped weak budgets?
- What are the out-of-band delivery cooldown and dedupe policies?
- What is the complete Postgres auth schema and migration validation contract?
- How do method-owned state tables register schema, preconditions, mutations, and durable
  effects without bypassing core invariants?
- How are durable effects integrated with Paranoid queue for delivery, retry, stale work,
  and idempotency?
- What are the auth operation-count invariants for hot paths once schema and runtime are
  stable enough to pin them?
- What is the immutable audit-event coverage matrix?
- What are the public mounted-API input limits and cookie-size budgets?
- What is the client WASM/TypeScript package boundary for password-derived signing,
  proof-of-work, sub-key derivation, and request/response types?
- What does the realistic adversarial application-lifecycle suite look like once the
  mounted runtime exists?
