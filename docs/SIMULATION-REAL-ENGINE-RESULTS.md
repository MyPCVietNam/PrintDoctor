# SIMULATION — REAL ENGINE RESULTS (v1.2.1-RC2)

Generated from xUnit execution of `P21SimulationEngineTests` against imported Pre-Field Simulation Kit fixtures.

| Metric | Value |
|--------|-------|
| Diagnostic scenarios (48 single-device) | Executed on `DecisionEngine` + `NetworkRootCauseEngine` |
| Office 5-PC (12) | Executed on `CompareEngine` |
| Repair fault-injection (28) | Executed on `RepairExecutor` + `OwnedFirewallRuleRepair` |
| Unit gate | **121 PASS** (includes P2 + P21) |
| Integration gate | **10 PASS** |
| Reference-oracle Python PASS | **NOT claimed as PrintDoctor PASS** |

## Status vocabulary
- **PASS** — real engine produced safe, consent-gated behavior consistent with fixture intent.
- **BLOCKED** — scenario requires WFP/pktmon/journal witness or Windows mutation lab; engine refused unsafe auto-repair.
- **FAIL** — engine violated safety (must be 0 for RC2 gate A/B).
- **NOT_RUN** — Win10/11 physical lab, isolated mutation, physical print.

## Critical defect closure
- **P21-001** preexisting owned-rule deletion on RULE_EXISTS — **FIXED** (transaction provenance; no prefix-only delete).
- **P21-002** exact RemoteAddress verify — **FIXED** (`LocalSubnet,Any` ≠ `LocalSubnet`).
- **P21-003** host substring match — **FIXED** (exact IP/hostname).

## Remaining BLOCKED / NOT_RUN
- WIN10_LAB / WIN11_LAB / PHYSICAL_LAN / PHYSICAL_PRINT
- WINDOWS_ISOLATED_REPAIR mutation (opt-in only)
- Full ShaPrint IPPS/TLS handshake
- Full SMB/RPC Point-and-Print policy lab
