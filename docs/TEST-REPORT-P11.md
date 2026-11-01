# TEST-REPORT — P1.1 HF2

| Gate | Result |
|------|--------|
| UNIT_PASS | PASS (86+) |
| INTEGRATION_PASS | PASS (4 + HF2 PowerShell fixtures; no firewall mutation in CI) |
| WINDOWS_CI_PASS | PENDING this push |
| WIN10_LAB_NOT_RUN | BLOCKED |
| WIN11_LAB_NOT_RUN | BLOCKED |
| PHYSICAL_LAN_NOT_RUN | BLOCKED |
| PHYSICAL_PRINT_NOT_RUN | BLOCKED |

HF2 regressions: remote-fail-before-enable, changed-rule verify, rollback RemoteAddress, Applied-without-Verify, cross-session recovery, multi-NIC selection, non-reversible redaction, wrong client Role, PrintBridge≠ShaPrint.

Windows fixtures: `tests/fixtures/powershell/firewall-safe-scope.assertions.md` + `Hf2WindowsPowerShellFixtureTests` (recording runner). Live mutation gated by `LPD_ALLOW_FIREWALL_MUTATION` (not set in CI).

Honest note: unit/fake + script-contract coverage ≠ Win10/11 physical LAN validation. Not FIELD READY.
