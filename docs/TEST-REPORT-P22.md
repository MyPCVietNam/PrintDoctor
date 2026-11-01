# Test report — v1.2.2-RC3

| Gate | Result | Notes |
|------|--------|-------|
| SOURCE_BUILD_PASS | PASS (local Linux) | `dotnet build` / test |
| UNIT_PASS | **138 PASS** | was 121 @ RC2; +P22 recovery/sim/ShaPrint |
| INTEGRATION_PASS | **10 PASS** | safe/isolated |
| SIMULATION_STRICT_PASS | **48 diagnostic + 12 office + 28 fault** | strict ExpectedMatches |
| FAULT_INJECTION_PASS | **28/28** | via real RepairExecutor |
| WINDOWS_API_PASS | PASS (read-only via Windows CI build/test host) | mutation tests not run on hosted runners |
| WINDOWS_CI_PASS | **PASS** | run [41327468569](https://github.com/MyPCVietNam/PrintDoctor/actions/runs/41327468569) @ `674c5ff` |
| ISOLATED_MUTATION_PASS | NOT_RUN | opt-in only; not on GitHub-hosted |
| WIN10_LAB_PASS | NOT_RUN | |
| WIN11_LAB_PASS | NOT_RUN | |
| PHYSICAL_LAN_PASS | NOT_RUN | |
| PHYSICAL_PRINT_PASS | NOT_RUN | |

**EXE SHA256:** `35d432268c8ed1055bd7e90ad2c4b17fa3bef8056a1e6f555e74e63bda5701a9`  
**RELEASE ZIP SHA256:** `167b2fc3b4063651b44d59d7dc7d888e663a50038541a6f32ef6d89f97488061`  

**FIELD_READY:** false
