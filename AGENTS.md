## Postgres Only / Connection Pooler Safe

All packages shall be designed for use with Postgres only and shall be safe for use with
connection poolers in transaction mode (or equivalent). It is prohibited to use advisory
locks, LISTEN/NOTIFY or any other Postgres features that require maintaining session-level
state across multiple transactions.

## SQLx Is The Blessed Postgres Substrate

Paranoid currently uses SQLx as its supported Postgres substrate. Paranoid owns pool
construction so it can preserve connection-pooler-safe defaults. Public DB wrappers may
expose supported SQLx pool and transaction accessors for application-owned queries, but
Paranoid internals must still be designed around literal Postgres semantics rather than
SQLx quirks.

Public errors and invariants should not depend on driver-specific accidentals. When
behavior depends on SQLSTATE, transactional guarantees, row locking, collation,
constraints, or timestamps, express and test that behavior as Postgres behavior.

## Consistent Philosophy / Package Composability

All packages shall use a consistent design philosophy and work well together.

## Public APIs

All public APIs shall be intentional, non-leaky, ergonomic, footgun-free, and
user-friendly.

Prefer namespaced, intention-revealing Rust modules over flat root exports. Do not expose
lower-level implementation primitives merely because tests or internals use them. If a
lower-level primitive is easy to misuse, keep it private and expose a higher-level
composition.

## No Conversational or Changelog Comments

It is prohibited to add conversational or changelog comments to source code files.

## Report All Issues. No Severity Labels. Never Triage.

When doing reviews or audits, the goal is to find and report **all** issues, not just a
subset and not just "critical" issues.

It is prohibited to triage, prioritize, rank, or categorize issues by severity or
priority.

It is also prohibited to use severity or priority language in review outputs (for example:
"critical", "major", "minor", "P0/P1/P2", "high/medium/low", or similar labels).

Findings shall be presented as a plain, exhaustive list of issues. If no issues are found,
state that explicitly.

## Tests Shall Never "Cheat"

One example of cheating is hardcoding or computing values to match the current
implementation in order to make a test pass, rather than testing what is in fact "correct"
(either spec-defined or logically or semantically obvious). Another example of cheating is
to add unjustified tolerances to tests to make them pass. Any type of retro-fitting,
mirroring, or scope hacking, or anything spiritually similar, is prohibited in test
suites.

A failing test that exposes a real bug or issue is ALWAYS a HUGE BLESSING, and we should
be CELEBRATING when that happens.

## Long, Clear Function/Method/Variable Names Are Good

When a short function/method/variable name is crystal clear, then that's fine. But if it's
anything less than obvious and abundantly clear to users, then make the name longer and
more descriptive until it is. `BuyInDollarsNoWait` is an infinitely better name than `Buy`
with a documentation comment explaining it's denominated in dollars and doesn't wait. The
classic way of stating this is that "code should be self-documenting where possible".

In every single case, we need the clearest possible name. There should be zero room for
confusion or potentially forgetting semantics. It should always be immediately and clearly
obvious what a thing does and how it behaves from the name itself.

Anything dangerous, especially, should have an extremely explicit,
impossible-to-misconstrue name.

## Getters That Make Database Calls Must Start With Verbs

Getters that make database calls must start with verbs.

## Stay DRY

Don't Repeat Yourself. Following DRY clarifies thinking, keeps building blocks
high-quality, and keeps context windows smaller. Within reason and using common sense,
never repeat complex logic that should be abstracted into a shared helper.

## Performance Is Always A Concern, And It's Non-Optional

So long as it doesn't undermine security or correctness, always write code such that it
results in the highest performance "bang for the buck", even if it's more difficult to
write. Wastefulness is a form of incorrectness.

## Correct, Ideal Code Is The Goal, Not Easy Migrations Or Backwards Compatibility

When analyzing code, do not get caught up in "the easiest way to update it" or "the way to
maintain backwards compatibility". The goal is always "what is the maximally correct and
ideal version of this code", regardless of potential breakages or level of refactor
effort. It's never OK to take the lazy approach to solving a problem; always strive for
the truly correct and ideal approach.

## Pre-Existing Code Comments Are Not Infallible

Do not automatically take code comments at face value. If you are suspicious of the
reasoning, logic, or accuracy of any comment, do not blindly trust it. Do your own
analysis.

## We Should Make No Assumptions On Behalf Of Applications

Anything that could conflict (filenames, table names, key prefixes, etc.) with any
independent choices an application could make shall be over-ridable by user configuration
settings. Further, the defaults should not be overly presumptuous. For example, always use
something like `__paranoid_` instead of `paranoid` for prefixes.

## Never Rely On Documentation To Smooth Over A Footgun, Bad API, or Bad Name

Never ever ever suggest to "document this clearly" when something is confusing, a footgun,
ambiguous, poorly named, or poorly designed. The answer is not documentation, it's better
names, better design, better internal robustness.

## Do Not Accumulate Cruft

Adding a bunch of helper methods that have no point other than setting a default for you
is bad. This isn't to say we shouldn't have convenience helpers. It's just to say that
each convenience helper should ACTUALLY add true convenience over other options, not just
more options. For example, we don't need a `reset()` function that sets a value to `0`
when you can easily just do `set(0)` (because calling `set(0)` is not actually any harder
than calling `reset()`).

## Compile-Time Safety for Database Connections vs Transactions

Functions that interact with the database must use Rust parameter types that enforce
correct usage at compile time, not runtime. Specifically:

1. **Must be in a transaction**: Take `&mut db::Tx<'_>` or a sealed transaction-only trait
   that `db::Pool` cannot implement.

2. **Must NOT be in a transaction**: Take `&db::Pool` or a pool-only trait that
   transactions cannot implement.

3. **Works with either**: Use an explicitly named internal abstraction only when the
   operation is genuinely safe and semantically identical for both a pool and a
   transaction.

The goal is to make misuse a compile error, not a runtime surprise. If a method would
behave incorrectly or dangerously when given the wrong database context, the type
signature must reject it.

Do not add broad public executor traits just for convenience. Shared executor abstractions
should be private or sealed unless there is a concrete, safe public use case.

## Rust Formatting And Checks

After editing Rust files, run `cargo fmt` for the affected package or workspace. After
editing non-Rust files, run `make non-rust-fmt`.

Prefer focused checks while iterating, then run the relevant confidence gate before
considering a task complete.

## Byte-Stable Database Semantics / Collation Safety

Paranoid database correctness must not depend on database-default collation, locale, or
other ambient text comparison settings.

Internal persisted values that are opaque identifiers, secrets, MACs, hashes, tokens,
ciphertext, random IDs, job IDs, or other byte material must be stored as `BYTEA`, with
explicit length/domain checks when length is fixed or bounded.

Internal persisted values that are intentionally textual and participate in equality,
uniqueness, lookup, ordering, prefix scans, cursor semantics, protocol state decisions, or
security/correctness invariants must be:

- validated or canonicalized by Rust types before binding;
- stored as `TEXT COLLATE "C"` or an explicitly validated bytewise-compatible `C`/`POSIX`
  collation;
- covered by schema validation that rejects default-collation or otherwise
  locale-sensitive text columns when an existing table is adopted;
- covered by tests that would fail if a migration or validation path regressed to
  default-collation text.

Default-collation `TEXT` must not participate in Paranoid correctness or security
semantics. Arbitrary application payload columns may use types such as `JSONB`, but
Paranoid internals must not rely on collation-sensitive comparisons inside those payloads
for correctness.

## Untracked Files and `*.human.*` Files

- Never edit or delete files matching `*.human.*` or `*.local.*` unless the user
  explicitly asks.
- For other untracked files:
    - If the file appears user-authored or pre-existing, do not edit/delete it unless the
      user explicitly asks.
    - If the file was created by you (the agent) as part of the current task, you (the
      agent) may edit/delete it as needed to complete the task.

## Don't Add Non-Conflicted Makefile Targets to .PHONY

Unless there's an actual conflict with a file or directory on disk, it's just cruft.

## Path Hygiene

- Never, ever commit machine-specific absolute paths (for example, `/Users/...`) into
  repository files.
- Use repository-root-relative paths in docs and instructions.
