# WINDOWS-API-VALIDATION

| Check | Status |
|-------|--------|
| NetSecurity cmdlet discovery (read-only) | Windows CI integration test `P2_00A_LiveWindows_NetSecurityParameterBinding_ReadOnly` |
| `Set-NetFirewallAddressFilter` lacks `-AssociatedNetFirewallRule` | Asserted on windows-latest |
| `Set-NetFirewallRule -RemoteAddress` present | Asserted |
| Production scripts free of invalid Set+Associated | Unit catalog scan |
| Firewall mutation on GitHub-hosted runner | **FORBIDDEN** (no `LPD_ALLOW_FIREWALL_MUTATION`) |
| Win10 22H2 / Win11 desktop lab | **LAB_NOT_RUN** |

Read-only scripts from simulation kit: `tests/Simulation/windows-readonly/`.
