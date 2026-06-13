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

## Questions That Need Technical Design

These do not need an immediate maintainer answer unless the design exposes a real
tradeoff. They need a concrete design before implementation continues downstream.

- Are there any public-alpha subject-targeted delayed actions beyond out-of-band
  identifier change and subject-auth-state deletion that need their own records,
  preconditions, notices, cancellation rules, expiry rules, and execution rules?
- Should Paranoid ever expose an arbitrary custom-method registry after public alpha, and
  if so, what reviewed contract is strong enough for application-supplied methods without
  letting them own proof sufficiency, lifecycle authority, cookies, CSRF, audit,
  revocation, queue ordering, schema drift policy, or method-work atomicity?
- How should public unauthenticated out-of-band challenge dedupe bound delivery harassment
  without letting one browser create an unusable challenge that blocks another browser
  from starting a usable ceremony for the same recipient/window?
- What are the final public names and type shapes for exposing mounted route manifest
  input-limit metadata once auth leaves private WIP?
- What is the client WASM/TypeScript package boundary for password-derived signing,
  proof-of-work, sub-key derivation, and request/response types?
- What does the realistic adversarial application-lifecycle suite look like once the
  mounted runtime exists?
