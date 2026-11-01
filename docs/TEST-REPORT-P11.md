# TEST-REPORT — P1.1 HF2 final correction (v1.1.3)

| Gate | Result |
|------|--------|
| UNIT_PASS | PASS (94) |
| INTEGRATION_PASS | PASS (9; no firewall mutation in CI) |
| WINDOWS_CI_PASS | PASS — https://github.com/MyPCVietNam/PrintDoctor/actions/runs/41313515087 |
| WIN10_LAB_NOT_RUN | BLOCKED |
| WIN11_LAB_NOT_RUN | BLOCKED |
| PHYSICAL_LAN_NOT_RUN | BLOCKED |
| PHYSICAL_PRINT_NOT_RUN | BLOCKED |

## HF2 correction regressions
- Verify=false + RollbackVerified=false → UNCERTAIN_STATE
- Applied + rollback failed → UNCERTAIN_STATE
- Corrupt journal → CORRUPT_JOURNAL / BLOCKED
- Executor with unfinished prior tx → Apply blocked
- Rollback only transaction ChangedRuleIds
- PowerShell collector fail → UNKNOWN (no fake PASS)
- PARTIAL_CHANGED parsed on Apply failure

Honest note: code safety closed for these defects at unit/fixture level. Live Windows read-only lab still required before FIELD READY. Not FIELD/PRODUCTION READY.
