# Changelog — v1.1.0 (P1.1)

## Fixed (critical)

- Removed no-op repair Apply/Verify paths that reported false success.
- Wired real `FirewallIcmpEchoRepair`, `FilePrintShareRepair`, `NetworkProfilePrivateRepair` with backup/verify/rollback.
- `FW-FILE-PRINT-SHARE` no longer maps to ICMP repair.
- `RolledBack` only when rollback succeeded and verified; cancelled tokens are not reused for rollback.
- Durable repair journal with incomplete-Apply recovery.
- Replaced hardcoded UNC / sharing / ShaPrint listen / third-party / discovery placeholders with collectors that return Pass/Fail/Unknown/NotTested/AuthDenied.
- Real `Get-NetRoute`, `Get-NetNeighbor`, `Get-NetConnectionProfile`, `Get-NetIPInterface` collection; interface metric is no longer InterfaceIndex.
- CompareEngine no longer treats empty probe sets as universal failure; Compare Reports imports real ZIP/JSON.
- ReportExporter redaction, ACL hardening (Windows), real repairs/before-after/event log sections (or explicit NOT_COLLECTED).

## Added

- `ProbeOutcome` model; `NotImplementedRepair`; `ReportCompareService`; P1.1 regression tests.
- Schema version `1.1.0`.

## Publish note

- `PublishSingleFile=false`: release is **self-contained multi-file** win-x64 (EXE + runtime dependencies), not a single standalone EXE.

## Explicit non-claims

- Not FIELD READY / PRODUCTION READY until WIN10/WIN11 lab and physical LAN/print validation complete.
