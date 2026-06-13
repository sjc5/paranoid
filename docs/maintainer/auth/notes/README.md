# Auth Notes

This directory has one canonical current auth design note, one active roadmap, one
implementation audit ledger, and one short open-question note:

- `AUTH_DESIGN.md`
- `AUTH_ROADMAP.md`
- `AUTH_IMPLEMENTATION_LEDGER.md`
- `AUTH_OPEN_QUESTIONS.md`

The raw notes in `docs/maintainer/auth/raw-notes.local/` are source material for design
intent, not implementation instructions. They contain old code, rejected branches, and
inconsistent sketches. Do not edit them.

Do not add another overlapping auth audit or recalibration note. If the current model is
wrong or incomplete, update `AUTH_DESIGN.md`. If sequencing or completion state changes,
update `AUTH_ROADMAP.md`. If a decision is still open, update `AUTH_OPEN_QUESTIONS.md`. If
live implementation audit findings change, update `AUTH_IMPLEMENTATION_LEDGER.md`.
