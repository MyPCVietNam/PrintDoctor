# Changelog — v1.1.4 (final two safety defects)

## DEFECT 1 — Mutation before tracking
- Snapshot rule state before any Set-*.
- Record durable `$tracked` / ChangedRuleIds **before** the first Set-NetFirewall*.
- Scope while Disabled; Enable only after LocalSubnet confirmed (no Enabled+wide-scope window).
- On mutation failure: controlled `Restore-RuleSnap` for tracked ids only.
- ROLLBACK_FAIL ⇒ `UNCERTAIN_STATE` (never Clean).

## DEFECT 2 — Empty journal fail-open
- Existing `repair-journal.json` that is empty/whitespace ⇒ `IsCorrupt` / `CorruptJournal`.
- Missing file still Clean (fresh session).
- Corrupt journal refused overwrite; executor returns BLOCKED.

## Non-claims
Windows physical / read-only field lab still **BLOCKED**. Not FIELD/PRODUCTION READY.
