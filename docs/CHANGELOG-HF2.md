# Changelog — v1.2.2-HF2

Critical field-pilot hotfix for unreadable dark UI and “SCAN does nothing” status/busy bugs.
Safe Repair engines, journals, and simulation tests are **unchanged** (Gate I).
FIELD_READY remains **false** until Windows visual lab + field pilot sign-off.

## Gate A — Explicit dark theme
- Palette: `#0B0F16` / `#171D28` / `#202838` / `#F2F4F8` / `#BBC5D3` / `#E0B84A` / `#3DDC97` / `#F1C453` / `#FF7474`
- Explicit styles for TextBlock, Label, RadioButton, TextBox, ComboBox, ListBox/Item, Button, ToolTip, ProgressBar, status
- Dark text (`#0B0F16`) on yellow primary buttons; Vietnamese-capable font stack
- WCAG AA contrast covered by unit contracts UI-001/002

## Gate B / G — Layout & permanent status
- Header → connection/mode → **persistent status strip** → results/repair → bottom actions
- Status/progress never buried in a clipped StackPanel
- Empty state: `Chưa kiểm tra — nhấn KIỂM TRA để bắt đầu.`
- Phases: READY / VALIDATING / SCANNING / COMPLETED / FAILED / CANCELLED
- Window sized for 1100×720–1920×1080 (Min 960×640)

## Gate C — Robust async scan
- `AsyncRelayCommand` with explicit `RaiseCanExecuteChanged`
- `IsBusy` raises `PropertyChanged`; cancel via `CancellationTokenSource`
- Elapsed timer + stage progress; exceptions logged & surfaced; busy released in `finally`
- No CommunityToolkit dependency (justified: tiny local command suffices)

## Gate D — Quick vs Deep
- Quick: concurrent connectivity, fewer ports/services, skip routes/neighbors/printers/third-party
- Deep: full prior inventory path
- UNKNOWN ≠ FAIL in display normalization + DecisionEngine (preserved)

## Gate E — Server / Client
- Server = local only (remote IP hidden); Client requires target
- Vietnamese mode indicator

## Gate F — Errors & logs
- Visible FAILED status + ProgramData logs with LocalAppData/temp writability fallback
- Optional icacls when ProcessRunner available
- **SAO CHÉP CHI TIẾT LỖI / COPY ERROR DETAILS**

## Gate H — Tests
- UI-001…UI-015 unit contracts; `UI_VISUAL_LAB_NOT_RUN` without real Windows desktop
- Full unit + integration suites green on Linux agent; Windows CI authoritative for WPF publish

## Gate I — Safe Repair
- No rewrite of RepairExecutor / owned firewall / journal recovery
- Scan errors never auto-apply repairs

## Gate J — Delivery
- Version **1.2.2-HF2** on PR #4 branch `cursor/p21-simulation-repair-hardening-e81e`
- Artifacts: FULL / CHANGED / RELEASE ZIPs + SHA256 + MANIFEST + reports
