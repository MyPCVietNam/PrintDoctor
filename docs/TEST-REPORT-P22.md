# Test report — v1.2.2-RC3

| Gate | Result | Notes |
|------|--------|-------|
| SOURCE_BUILD_PASS | PASS (local Linux) | `dotnet build` / test |
| UNIT_PASS | **138 PASS** | was 121 @ RC2; +P22 recovery/sim/ShaPrint |
| INTEGRATION_PASS | **10 PASS** | safe/isolated |
| SIMULATION_STRICT_PASS | **48 diagnostic + 12 office + 28 fault** | strict ExpectedMatches |
| FAULT_INJECTION_PASS | **28/28** | via real RepairExecutor |
| WINDOWS_API_PASS | PENDING Windows CI | read-only NetSecurity validation on runner |
| WINDOWS_CI_PASS | PENDING | push triggers `windows-build.yml` |
| ISOLATED_MUTATION_PASS | NOT_RUN | opt-in only; not on GitHub-hosted |
| WIN10_LAB_PASS | NOT_RUN | |
| WIN11_LAB_PASS | NOT_RUN | |
| PHYSICAL_LAN_PASS | NOT_RUN | |
| PHYSICAL_PRINT_PASS | NOT_RUN | |

**FIELD_READY:** false
