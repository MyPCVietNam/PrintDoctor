# Changelog — v1.2.1-RC2

## GATE A — Safety
- **P21-001:** Owned firewall rollback deletes only transaction-created rules (fingerprint/provenance); RULE_EXISTS never destructive.
- **P21-002:** Exact RemoteAddress/Profile verification; reject `LocalSubnet,Any` / `0.0.0.0/0`.
- **P21-003:** Exact host/IP probe matching (no substring).
- Machine-level repair lock; NoChange / Blocked exception paths; LOCAL_CONFIG_VERIFIED ≠ end-to-end FIXED.

## GATE B — Simulation
- Imported Pre-Field Simulation Kit fixtures (48+12+28).
- Real-engine xUnit harness + mapping docs.

## GATE C — Wiring / UX
- DecisionEngine emits FW-OWNED-SMB445 / FW-OWNED-SHA48631 with evidence gates.
- Repair selection ListBox (no MessageBox cascade for primary choice).
- SHA-START-PROCESS explicitly NOT_IMPLEMENTED.

## CI
- WINDOWS_CI_PASS @ `91655ab` — https://github.com/MyPCVietNam/PrintDoctor/actions/runs/41323169805
- Unit 121 / Integration 10 PASS on windows-latest

## Non-claims
FIELD_VALIDATION_PENDING. Physical lab NOT_RUN. Not Production Ready.
