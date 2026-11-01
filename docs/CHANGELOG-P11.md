# Changelog — v1.1.2 (P1.1 HF2)

## Final safety gate (HF2)

### Firewall strict scope
- Removed empty `catch` around `Set-NetFirewallAddressFilter`.
- Enable never runs unless Profile=Private and RemoteAddress=LocalSubnet re-read succeeds.
- Empty RemoteAddresses is **not** LocalSubnet evidence.
- Verify checks **all changed rule ids** (recorded list), not “any matching rule”.
- Approved FPS rule ids only; no `-Group` enable; Public rules untouched.

### Exact rollback
- Restore sets Profile/Direction/Action/RemoteAddress before enable/disable.
- Re-read `MatchesBackupSnapshot`; RemoteAddress restore failure ⇒ PARTIAL_ROLLBACK, never Verified=true.

### Crash recovery across sessions
- `Applied` without `Verify` ⇒ UNCERTAIN_STATE.
- `RepairJournal.ScanAllSessions` blocks further repairs until technician review (no auto-rollback).

### Network profile target
- Explicit InterfaceIndex required; Preview shows Alias/IP/GW/Category; InterfaceIndex=? refused.

### Privacy & ShaPrint
- Ephemeral HMAC tokens (key not in ZIP); not raw SHA256(IP).
- ShaPrint listeners require ShaPrint executable path/PID — PrintBridge ≠ ShaPrint (FOREIGN_PROCESS/PORT_CONFLICT).

### Regression / CI
- HF2 unit suite + PowerShell script-contract fixtures (`Hf2WindowsPowerShellFixtureTests`, recording runner).
- CI never mutates production firewall; live mutation gated by `LPD_ALLOW_FIREWALL_MUTATION`.

## Non-claims
Windows 10/11 + physical LAN still NOT_RUN. Not FIELD/PRODUCTION READY. Fake unit tests do not close Windows compatibility alone.
