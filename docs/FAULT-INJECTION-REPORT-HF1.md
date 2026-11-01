# FAULT-INJECTION-REPORT — v1.2.2-HF1

All 28 repair scenarios execute through `RepairExecutor` (or crash-recovery reinit / wrong-target findingOwner).  
No fabricated `RepairResult` is counted as an executed repair test.

Required result fields per scenario:  
`scenarioId, expected, actual, executionPath, engineInvoked, mutationAttempted, rollbackAttempted, rollbackVerified, verdict, evidence`

See `docs/p22/FAULT-INJECTION-RESULTS.json` for the machine-readable run captured with this HEAD.

Semantics enforced:
- **ROLLED_BACK** ⇒ rollbackAttempted ∧ rollbackVerified
- **BLOCKED** ⇒ system not left mutated (Applied false or rollback verified)
- **UNCERTAIN_STATE** ⇒ further mutation blocked via journal recovery
- Journal write failure ⇒ BLOCKED (fail closed)
