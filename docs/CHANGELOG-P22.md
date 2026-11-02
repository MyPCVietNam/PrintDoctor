# Changelog — v1.2.2-RC3

Baseline: `22ebbf9` (v1.2.1-RC2 docs) / impl `91655ab`.

## GATE A — Critical safety
- **P22-001:** Shared `TransactionId` via `ITransactionBoundRepair`; before-state PRESENT/ABSENT/UNKNOWN; create Disabled → verify → Enable; recover orphans via provenance re-query; `ROLLBACK_VERIFIED` / `PARTIAL_ROLLBACK` / `UNCERTAIN_STATE`.
- **P22-002:** Strict `MatchesDesired` (NULL≠VALID, Any≠port/ICMP); CIDR parser; reject `SPECIFIC_CIDR` / `0.0.0.0/0` / `::/0`.
- **P22-003:** Machine-wide ProgramData (+ named mutex) lock independent of SessionId; acquire lock **before** journal recovery; executor binds TransactionId.

## GATE B — Strict simulation
- **P22-004:** Removed permissive `ExpectedMatches` fallback; role from scenario input (not `expected.owner`); 48+12+28 through real engines; fault-injection via `RepairExecutor` + controlled runners.

## GATE C — Office repairs
- Service findings now set `RepairOwner` (SVC-* visible in UI).
- `SHA-START-PROCESS` implemented with verified executable identity (never kill foreign).
- `FW-OWNED-SHA48633` suggested when UDP 48633 listens.
- `NET-MS-SERVER-BINDING` / `PRN-RESTORE-MAPPING` explicitly NOT_IMPLEMENTED with reasons.

## GATE D — UX
- Vietnamese `LOCAL_CONFIG_VERIFIED — WAITING_FOR_CLIENT_VERIFICATION` status (never FIXED from PowerShell alone).
- Existing SCAN → repair ListBox workflow retained.

## Non-claims
`FIELD_READY=false`. Physical Win10/11 LAN + print confirmation **NOT_RUN**.
