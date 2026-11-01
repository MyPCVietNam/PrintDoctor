# FAULT-INJECTION-REPORT — 28 repair scenarios

All 28 IDs from `repair_scenarios.json` executed through real `RepairExecutor`.

Coverage groups:
- Precondition: no consent, wrong role, no admin, GPO, LocalPolicyMerge disabled, third-party, Public profile, RemoteAddress=Any, unknown repair, foreign rule, ShaPrint foreign PID.
- Transaction: corrupt/uncertain journal, journal write fail, crash after intent/create.
- Rollback: scope verify fail, enable fail, local/remote verify fail, rollback fail → UNCERTAIN.
- Happy paths: VERIFIED ICMP/SMB/ShaPrint/CIDR; NO_CHANGE duplicate owned rule.

**Result:** 28/28 mapped PASS against real executor semantics (not the Python reference model).
