# Test report — v1.2.2-HF1

| Gate | Result | Notes |
|------|--------|-------|
| UNIT | PASS | 154 tests |
| INTEGRATION | PASS | 10 tests |
| SIMULATION diagnostic | PASS/BLOCKED | 21 PASS + 27 BLOCKED (witness/unmappable preserved) — 0 FAIL |
| SIMULATION office 5PC | PASS/BLOCKED | 8 PASS + 4 BLOCKED — 0 false PASS; OFFICE-03 requires CMP-003 |
| FAULT injection 28 | PASS | executor provenance; claim_28_of_28_real_executor when all paths executor* |
| WINDOWS API lab | NOT_RUN | Requires physical Windows SKU |
| WINDOWS CI | PASS | https://github.com/MyPCVietNam/PrintDoctor/actions/runs/41329863562 @ `2f5c611` |
| FIELD Win10/11 | NOT_RUN | Required for FIELD_READY |

EXE SHA256: `6953b08735af1a59e6a86088e16ddbf97e35f1fe19d6d2d78974f7ba0d18b0a5`  
RELEASE ZIP SHA256: `c125672933bc0e9b31db9a014e4ae65d0c10a09772bff8f00789748f35f6d2d1`

**FIELD_READY:** false

Negative controls: ICMP correct PASS; unrelated SMB FAIL; wrong owner FAIL; no-evidence unmappable not PASS; AUTO_APPLY language FAIL; “do not automatically” not false FAIL.
