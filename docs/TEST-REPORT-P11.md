# TEST-REPORT — v1.1.4 final two safety defects

| Gate | Result |
|------|--------|
| UNIT_PASS | PENDING this push |
| INTEGRATION_PASS | PENDING this push |
| WINDOWS_CI_PASS | PENDING this push |
| WIN10_LAB_NOT_RUN | BLOCKED |
| WIN11_LAB_NOT_RUN | BLOCKED |
| PHYSICAL_LAN_NOT_RUN | BLOCKED |
| PHYSICAL_PRINT_NOT_RUN | BLOCKED |

## Final two defect regressions
- D1: Set-NetFirewallRule PASS + AddressFilter FAIL → intent tracked; rollback OK or UNCERTAIN_STATE
- D1: PS script records `$tracked.Add` before first Set-NetFirewall*
- D2: empty/whitespace journal → CorruptJournal; ScanAllSessions; Executor BLOCKED; no overwrite
- D2: missing journal file → Clean (not corrupt)

Honest note: unit/fixture ≠ Windows physical lab. Not FIELD READY.
