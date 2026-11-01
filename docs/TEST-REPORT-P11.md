# TEST-REPORT — P1.1

## Gates

| Gate | Result |
|------|--------|
| UNIT_PASS | PASS (59 unit tests) |
| INTEGRATION_PASS | PASS (4 safe integration tests) |
| WINDOWS_CI_PASS | PENDING (await GitHub Actions on `fix/p11-diagnostic-accuracy-safe-repair`) |
| WIN10_LAB_NOT_RUN | NOT_RUN / BLOCKED (no Win10 lab in this agent) |
| WIN11_LAB_NOT_RUN | NOT_RUN / BLOCKED |
| PHYSICAL_LAN_NOT_RUN | NOT_RUN / BLOCKED |
| PHYSICAL_PRINT_NOT_RUN | NOT_RUN / BLOCKED |

## Local execution (Cloud Linux agent)

```text
dotnet test MyPC.LanPrintDoctor.sln -c Debug
  UnitTests:        59 passed
  IntegrationTests:  4 passed
```

## Regression coverage (P11RegressionTests)

- Fake-success / NOT_IMPLEMENTED / FPS≠ICMP / rollback honesty / journal recovery
- UNC NotTested / AuthDenied; ShaPrint listen / not listen / not installed
- Sharing Fail / Unknown; Compare empty.All; Compare ZIP/JSON import; redaction

## Explicit non-claims

This report does **not** claim FIELD READY, PRODUCTION READY, or verified physical LAN/printer/ShaPrint outage reproduction.
