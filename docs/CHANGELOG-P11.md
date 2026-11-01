# Changelog — v1.1.3 (P1.1 HF2 final correction)

## HF2 final correction (safety)

### RepairJournal recovery
- `IsUncertain` evaluates **Phase and Success**.
- `Verify=false` and `RollbackVerified=false` never count as completed.
- Unreadable journal JSON ⇒ `CorruptJournal` / **CORRUPT_JOURNAL** (never Clean).
- `ScanAllSessions` detects Uncertain, Incomplete, and Corrupt across sessions.

### RepairExecutor
- Prior `UNCERTAIN_STATE`, `INCOMPLETE`, or `CORRUPT_JOURNAL` ⇒ immediate **BLOCKED**.
- No warn-and-continue into Apply (engine-level; UI-independent).

### Firewall rollback scope
- Capture `ChangedRuleIds` even on mid-Apply failure (`PARTIAL_CHANGED`).
- Rollback restores **only** transaction-changed rules; unrelated/Public rules untouched.
- Never claim Verified without full backup re-read match.

## Non-claims
Windows 10/11 physical LAN read-only labs still **BLOCKED / NOT_RUN**. Not FIELD/PRODUCTION READY.
