# Field Test Kit — v1.2.2-HF1

**FIELD_READY: false.** Use Windows CI RELEASE ZIP only.

## Bundle
- `FIELD-TEST-CHECKLIST-HF1.md` — 12-step two-PC then remaining clients
- `OPERATION-GATING-HF1.md` — per-operation enablement
- This README

## Workflow
1. Server read-only scan → `SERVER-BEFORE.zip`
2. First client read-only scan → `CLIENT-BEFORE.zip`
3. Compare → best-supported cause
4. At most one consented eligible repair (skip if switch/VLAN/routing/IP-conflict)
5. Journal + snapshot → local verify → client re-probe → AFTER zips → physical print ask
6. Only then remaining clients

Rollback / unfinished txs: `%ProgramData%\MyPC\LanPrintDoctor` — further Apply blocked until review.
Machine lock: `Global\MyPC.LanPrintDoctor.MachineRepair` (fail closed).
