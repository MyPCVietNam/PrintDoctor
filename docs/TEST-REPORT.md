# TEST-REPORT

See also `TEST-REPORT-P11.md` for the P1.1 gate table.

## Local (Cloud Linux agent)

- Unit: 59 passed (includes P1.1 regression suite)
- Integration (safe): 4 passed
- Scenarios covered in DecisionEngineScenarioTests: 1–25 (mocked/fake adapters)

## Windows CI

Populated by `.github/workflows/windows-build.yml` artifact `TEST-SUMMARY.md`.

## Explicit non-claims / blocked gates

| Gate | Status |
|------|--------|
| UNIT_PASS | PASS |
| INTEGRATION_PASS | PASS |
| WINDOWS_CI_PASS | See latest Actions run on branch |
| WIN10_LAB_NOT_RUN | NOT_RUN / BLOCKED |
| WIN11_LAB_NOT_RUN | NOT_RUN / BLOCKED |
| PHYSICAL_LAN_NOT_RUN | NOT_RUN / BLOCKED |
| PHYSICAL_PRINT_NOT_RUN | NOT_RUN / BLOCKED |

This report does **not** claim FIELD READY or PRODUCTION READY.
