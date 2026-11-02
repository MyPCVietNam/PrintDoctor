# Changelog — v1.2.2-HF1

Corrective hotfix on RC3. No broad rewrite. FIELD_READY remains **false**.

## GATE A — Diagnostic simulation truth
- Removed “any finding ⇒ PASS” and always-true owner fallbacks in `SimulationScenarioMapper`
- Explicit AcceptedEngineIds / UnmappableFindings; severity/owner/evidence checks
- unsafeAuto only on affirmative silent-apply language (not “do not … automatically”)
- Negative-control unit tests for ICMP vs SMB, wrong owner, no evidence, empty LOCAL

## GATE B — Office 5-PC
- `ClassifyOffice` never receives expected labels
- Wire Neighbors / MAC / NIC / ShaPrint observations into CompareEngine inputs
- CMP-000/003/004/005 classifications; power/WFP/packet/RPC without models → **BLOCKED**
- CMP-001 alone cannot satisfy IP-conflict expectations
- Mutation test rejects false PASS

## GATE C — Repair fault-injection provenance
- All representable scenarios execute through `RepairExecutor` (+ policy/prereq layer)
- No fabricated `RepairResult` counted as executed repair
- Crash = interrupted journal + reinitialized executor
- Result schema: scenarioId, expected, actual, executionPath, engineInvoked, mutationAttempted, rollbackAttempted, rollbackVerified, verdict, evidence
- Journal write failure fail-closed (BLOCKED, no mutation)

## GATE D — ShaPrint trust
- Canonical path; Program Files root; reparse reject; metadata/hash when available
- Filename-only trust rejected; no foreign kill; start ≠ IPPS
- Trust failure disables start with manual instruction

## GATE E — Machine-wide lock
- Windows production requires Global mutex; no silent per-user fallback
- Unwritable lock dir / mutex permission denied → fail closed
- Abandoned mutex recovery preserved; incomplete tx recheck under lock

## GATE F/G — Gating + field pilot
- Operation gating matrix; prohibited insecure ops unchanged
- Field checklist: two-PC then remaining clients; LOCAL ≠ E2E ≠ PHYSICAL

## GATE H
- Version **1.2.2-HF1**; unit + integration + strict sim + fault injection
- Windows CI hashes recorded after CI completes (not reused from RC3)
