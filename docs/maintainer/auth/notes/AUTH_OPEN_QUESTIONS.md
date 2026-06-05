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
- What default and minimum delay policies should Paranoid provide for email-only password
  reset, second-factor reset, and destructive account deletion?
- What lifecycle mutations should require immediate subject-wide revocation, step-up
  freshness, delayed execution, or some combination of those controls?
- What product shape should Paranoid expose for admin/support recovery intervention?

## Questions That Need Technical Design

These do not need an immediate maintainer answer unless the design exposes a real
tradeoff. They need a concrete design before implementation continues downstream.

- How should mounted flows generate, display, store, rotate, and regenerate user-visible
  recovery codes through first-party method code rather than test-only method work?
- What are the complete pending-action records, preconditions, notices, cancellation
  rules, expiry rules, and execution rules for delayed second-factor reset, delayed
  credential replacement scheduling, and other non-deletion subject-targeted waits?
- How should second-factor reset be expressed as a lifecycle policy role over credential
  reset without turning it into a separate credential kind?
- What is the complete Postgres auth schema and migration validation contract, including
  method-owned table validation at the same rigor as core auth tables?
- How do method-owned state tables register schema, preconditions, mutations, reset work,
  replacement work, regeneration work, and durable effects without bypassing core
  invariants?
- How are auth durable effects integrated with Paranoid queue for delivery, retry, stale
  work, idempotency, and operator visibility?
- What are the auth operation-count invariants for hot paths once schema and runtime are
  stable enough to pin them?
- What is the immutable audit-event coverage matrix?
- What are the public mounted-API input limits and cookie-size budgets?
- What is the client WASM/TypeScript package boundary for password-derived signing,
  proof-of-work, sub-key derivation, and request/response types?
- What does the realistic adversarial application-lifecycle suite look like once the
  mounted runtime exists?
