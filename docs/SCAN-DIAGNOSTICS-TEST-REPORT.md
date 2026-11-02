# Scan Diagnostics Test Report — v1.2.2-HF2

| Field | Value |
|-------|-------|
| Version | 1.2.2-HF2 |
| Audited baseline | `6ed5d1c2e7853baf720fbdd74311bbf38fed85ec` |
| Linux agent unit | **170 passed** |
| Linux agent integration | **10 passed** |
| Windows CI | **PASS** https://github.com/MyPCVietNam/PrintDoctor/actions/runs/41379102614 (170 unit / 10 integration) |

## Gate H — UI-001…UI-015

| ID | Focus | Result |
|----|-------|--------|
| UI-001 | Theme palette tokens | PASS |
| UI-002 | WCAG AA contrast (text/panel, dark-on-gold) | PASS |
| UI-003 | Empty state Vietnamese copy | PASS |
| UI-004 | READY…CANCELLED phase labels | PASS |
| UI-005 | Server mode hides remote target | PASS |
| UI-006 | Client mode requires target | PASS |
| UI-007 | UNKNOWN ≠ FAIL normalization | PASS |
| UI-008 | Quick vs Deep actually different | PASS |
| UI-009 | Progress stages + cancel | PASS |
| UI-010 | Exceptions propagate | PASS |
| UI-011 | AppLogWriter fallback + error details | PASS |
| UI-012 | IsBusy gates CanExecute | PASS |
| UI-013 | finally releases busy | PASS |
| UI-014 | Server scan ignores client IP field | PASS |
| UI-015 | Visual lab marker | **UI_VISUAL_LAB_NOT_RUN** |

## Orchestrator Quick vs Deep (summary)

| Aspect | Quick | Deep |
|--------|-------|------|
| Routes / Neighbors | skipped (NotTested) | collected |
| TCP ports to target | 445 + ShaPrint | 445, 135, 9100, ShaPrint |
| Services | Spooler + Lanman* | + FDResPub, SSDPSRV, upnphost |
| Shares / Printers | shares skipped; printers skipped | full |
| Third-party security | NotTested | collected |
| Connectivity | `Task.WhenAll` concurrent | `Task.WhenAll` concurrent |
| Collector note | `ScanMode=QuickScan` | `ScanMode=DeepScan` |

## Simulation / Safe Repair regression
Pre-existing simulation + repair unit/integration suites remain green (Gate I — no Safe Repair rewrite).

## Honest NOT_RUN gates
- **UI_VISUAL_LAB_NOT_RUN** — no real Windows desktop on this agent (1100×720–1920×1080 @ 100–150% scaling not visually verified)
- **FIELD_VALIDATION_NOT_RUN** — two-PC field pilot not executed
- **WINDOWS_CI** — PASS on tip `2262a03` run 41379102614 (authoritative EXE/RELEASE hashes recorded)
