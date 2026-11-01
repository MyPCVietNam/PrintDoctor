# Changelog — v1.1.1 (P1.1 HF1)

## Security & diagnostic truth gate (HF1)

### FIXED — BLOCKER 01 Firewall scope
- Removed `Enable-NetFirewallRule -Group` wholesale enablement.
- ICMP/FPS repairs set **Profile=Private** and **RemoteAddress=LocalSubnet before Enable**.
- Verify requires full scope via `FirewallRuleScope` (not merely Enabled=true).
- GPO/PolicyStore-managed rules are skipped.

### FIXED — BLOCKER 02 Incomplete rollback
- Backup/restore compare Enabled, Profile, RemoteAddress (and related attributes).
- RollbackVerified only after re-read matches backup (not PowerShell `OK` alone).
- Per-execution `TransactionId`; durable `ApplyStarted` before mutation.
- Crash mid-Apply → `UNCERTAIN_STATE` (never auto-claim recovered).

### FIXED — HIGH 03 Unknown ≠ Fail
- `EvaluateNetwork` uses only decisive `ProbeOutcome.Pass|Fail`.
- Unknown/NotTested/NotApplicable never become LAN-001.

### FIXED — HIGH 04 Repair ownership
- Findings carry `RepairOwner`; client ICMP→server is `SERVER_ACTION_REQUIRED`.
- Executor/UI block local firewall repair for remote inbound issues.

### FIXED — HIGH 05 Report privacy
- Consistent redaction (stable tokens) across JSON/TXT/ZIP including routes, neighbors, probes, repairs, events, collector notes.
- ACL applied to session dir and export ZIP; icacls failures surface when required.

### FIXED — HIGH 06 Collectors / compare
- `EnableInsecureGuestLogons` from `Get-SmbClientConfiguration`.
- ShaPrint listeners filtered by owning PID.
- Network profile repair prefers primary interface (metric).
- Compare validates SchemaVersion/Role/SessionId/StartedAt; rejects oversized ZIP; notes redaction limits.

### FIXED — HIGH 07 Delivery integrity
- Packaging never emits a fake RELEASE ZIP; writes `RELEASE_BLOCKED.txt` instead.

## Explicit non-claims
Not FIELD READY / PRODUCTION READY until Win10/11 + physical LAN/print labs complete.
