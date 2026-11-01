# Changelog — v1.2.0-RC1 (P2 Field Pilot)

## P2-00 Critical Windows API & engine
- **P2-00-A:** Removed invalid `Set-NetFirewallAddressFilter -AssociatedNetFirewallRule` (not a Set-* parameter). Mutations use `Set-NetFirewallRule -RemoteAddress` / Get→pipe patterns. Live Windows parameter-binding probe on CI.
- **P2-00-B:** Strict Enabled parsing (`TryParseEnabled`) — `"False"` is never truthy.
- **P2-00-C:** Write-ahead durable journal (`MutationIntent` + WriteThrough flush) before Apply; corrupt journal fail-closed.

## P2-01 / P2-02 (RC1 slice)
- Network root-cause engine (CASE A/B/C, INFRASTRUCTURE_ACTION_REQUIRED).
- Owned firewall repairs: `MyPC.PrintDoctor.ICMPv4/SMB445/ShaPrint48631/ShaPrint48633.Private`.
- DecisionEngine prefers owned ICMP (`FW-OWNED-ICMP4`) over mutating system FPS rules.
- Safe Repair UI requires explicit user choice when multiple repairs exist.

## P2-03+ (partial / deferred for post-RC1)
- Service start repairs (Spooler/Lanman*) already present from P1.1.
- Advanced pktmon/WFP and recurrence baselines: P3 — not blocking RC1 P0/P1 gate.

## Non-claims
`FIELD_VALIDATION_PENDING`. Win10/11 physical lab **NOT_RUN**. Not FIELD/PRODUCTION READY.
