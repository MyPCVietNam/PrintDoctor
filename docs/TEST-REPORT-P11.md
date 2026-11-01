# TEST-REPORT — v1.2.0-RC1

| Gate | Result |
|------|--------|
| UNIT_PASS | **111 PASS** (local Linux; Windows CI pending push) |
| INTEGRATION_PASS | **9 PASS** (+1 Windows-only NetSecurity binding when on windows-latest) |
| WINDOWS_CI_PASS | PENDING push |
| WIN10_LAB_NOT_RUN | BLOCKED |
| WIN11_LAB_NOT_RUN | BLOCKED |
| PHYSICAL_LAN_NOT_RUN | BLOCKED |
| FIELD_VALIDATION_PENDING | **yes** |

## P2 regressions covered
1. Invalid NetSecurity parameter binding catalog + production script scan
2. Live Windows `(Get-Command …).Parameters.Keys` (windows-latest only)
3. Enabled `"False"` parsing
4. MutationIntent → UNCERTAIN; corrupt journal fail-closed
5. Root-cause CASE A / CASE B
6. Owned rule Disabled→Enable order; no Any remote; no 48632
7. Server prefers `FW-OWNED-ICMP4`
