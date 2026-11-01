# TEST-REPORT — v1.2.0-RC1

| Gate | Result |
|------|--------|
| UNIT_PASS | **111 PASS** (Windows CI) |
| INTEGRATION_PASS | **10 PASS** (Windows CI; includes live NetSecurity parameter-binding on windows-latest) |
| WINDOWS_CI_PASS | **YES** — https://github.com/MyPCVietNam/PrintDoctor/actions/runs/41321543958 |
| Commit | `824f292010db304afeba484f68b0a91092dd4875` |
| WIN10_LAB_NOT_RUN | BLOCKED |
| WIN11_LAB_NOT_RUN | BLOCKED |
| PHYSICAL_LAN_NOT_RUN | BLOCKED |
| FIELD_VALIDATION_PENDING | **yes** |

## P2 regressions covered
1. Invalid NetSecurity parameter binding catalog + production script scan
2. Live Windows `(Get-Command …).Parameters.Keys` (windows-latest)
3. Enabled `"False"` parsing
4. MutationIntent → UNCERTAIN; corrupt journal fail-closed
5. Root-cause CASE A / CASE B
6. Owned rule Disabled→Enable order; no Any remote; no 48632
7. Server prefers `FW-OWNED-ICMP4`
