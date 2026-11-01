# Defect fix matrix — P2.2 / v1.2.2-RC3

| ID | Defect | Fix | Verification |
|----|--------|-----|--------------|
| P22-001 | `_createdInThisTransaction` only after CHANGED; orphan creates miss rollback | Split create/enable; provenance Description; re-query recovery; ROLLBACK_VERIFIED | `P22FirewallTransactionRecoveryTests` |
| P22-002 | Permissive MatchesDesired (Any≡port/ICMP) | Strict typed compares; CIDR parser; reject placeholders | Same + `P21_002` / `P22_002_*` |
| P22-003 | Lock per session journal dir | Machine-wide lock; lock-then-recovery order | `P22_003_*` |
| P22-004 | Permissive ExpectedMatches; role from expected | Strict matchers; `ResolveRoleFromInput` | `P21SimulationEngineTests` 48+12+28 |
| P22-005 | Service repairs invisible / incomplete network path | RepairOwner on SVC findings; owned ICMP/SMB/profile | DecisionEngine + UI ListBox |
| P22-006 | SMB/RPC safety | No SMB1/signing/guest/RPC-open repairs; Spooler/LanmanServer start | Existing security tests + SVC owners |
| P22-007 | ShaPrint start stub | `ShaPrintStartRepair` verified exe only; SHA-005 UDP rule | `P22ShaPrintAndServiceOwnerTests` |
| P22-008 | Printer mapping auto | Explicit NOT_IMPLEMENTED `PRN-RESTORE-MAPPING` | CreateRepair stub |
| P22-009 | FIXED after PowerShell | LOCAL_CONFIG_VERIFIED VI/EN labels | MainViewModel |
| P22-010 | Field workflow | CompareReports + export retained; FIELD_READY false | Docs / checklist |
