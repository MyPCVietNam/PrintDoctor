# TEST-REPORT — P1.1 HF1

## Gates

| Gate | Result |
|------|--------|
| UNIT_PASS | PASS (76 unit tests incl. HF1 suite) |
| INTEGRATION_PASS | PASS (4) |
| WINDOWS_CI_PASS | PENDING (await Actions on PR #2 head) |
| WIN10_LAB_NOT_RUN | NOT_RUN / BLOCKED |
| WIN11_LAB_NOT_RUN | NOT_RUN / BLOCKED |
| PHYSICAL_LAN_NOT_RUN | NOT_RUN / BLOCKED |
| PHYSICAL_PRINT_NOT_RUN | NOT_RUN / BLOCKED |

## HF1 mandatory regressions

1. Public firewall rule unchanged  
2. Rollback restores profile/scope  
3. PS failure ≠ PASS  
4. Wrong-scope verify FAIL  
5. Unknown probes ≠ LAN-001  
6. Client ≠ server firewall repair  
7. ApplyStarted crash → UNCERTAIN_STATE  
8. Separate TransactionIds  
9. Redacted ZIP no IP/MAC leak  
10. Missing SchemaVersion rejected  
11. Foreign ShaPrint PID not counted  
12. No fake RELEASE ZIP  

## Non-claims

Not FIELD READY / PRODUCTION READY.
