# Defect fix matrix — P2.2 HF1 / v1.2.2-HF1

Baseline audited HEAD: `ce0099d` · Implementation baseline: `674c5ff`

| ID | Severity | Status | Defect | Fix | Tests |
|----|----------|--------|--------|-----|-------|
| HF1-A01 | BLOCKER | FIXED | FindingCategoryMatches any-finding fallback | Explicit AcceptedEngineIds only | Hf1NegativeControl*, P21 diagnostic |
| HF1-A02 | BLOCKER | FIXED | OwnerMatches always-true | Role/finding-defensible owners | Hf1NegativeControl* |
| HF1-A03 | HIGH | FIXED | unsafeAuto matched “do not automatically” | Affirmative AUTO_APPLY language only | SHA-15 PASS |
| HF1-B01 | BLOCKER | FIXED | ClassifyOffice leaked expected for POWER/SLEEP | BLOCKED:NO_POWER_STATE_MODEL | office5pc + mutation |
| HF1-B02 | BLOCKER | FIXED | OFFICE-03 PASS on CMP-001 alone | Neighbors→CMP-003 required | office5pc |
| HF1-B03 | HIGH | FIXED | Generic Compare finding satisfied specific diagnoses | Strict OfficeExpectedMatches | office5pc |
| HF1-C01 | BLOCKER | FIXED | Fabricated RepairResult for policy/journal | PolicyGatedRepair + executor path | fault-injection 28 |
| HF1-C02 | HIGH | FIXED | Journal write fail uncaught / mutated | Executor JOURNAL_WRITE_FAIL BLOCKED | R-17 |
| HF1-D01 | BLOCKER | FIXED | ShaPrint filename-only trust | EvaluateExecutableTrust ProgramFiles+meta | Hf1LockAndTrust* |
| HF1-E01 | BLOCKER | FIXED | Silent per-user lock fallback | Global mutex mandatory on Windows prod | MachineRepairLock |
| HF1-F01 | MED | FIXED | Stale RC3 field docs / CI PENDING claims | HF1 docs + gating matrix | docs |
| HF1-G01 | MED | FIXED | Field pilot package incomplete | FIELD-TEST-KIT HF1 12-step | kit |

Preserved prior BLOCKED witness scenarios (no force PASS): power/sleep, WFP confirm, packet-arrival, printer RPC, and other UnmappableFindings.
