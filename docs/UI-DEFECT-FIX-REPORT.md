# UI Defect Fix Report — v1.2.2-HF2

| Field | Value |
|-------|-------|
| Product | MyPC LAN & Print Doctor |
| Version | 1.2.2-HF2 |
| Audited baseline | `6ed5d1c2e7853baf720fbdd74311bbf38fed85ec` |
| PR | https://github.com/MyPCVietNam/PrintDoctor/pull/4 |
| Branch | `cursor/p21-simulation-repair-hardening-e81e` |

## Field blockers addressed

### 1) Dark/black text on dark panels (unreadable)
**Root cause:** Most `TextBlock`/`RadioButton`/`ListBoxItem` controls relied on system default foreground (often black) while panels used dark brushes. Only a subset of elements set `Foreground` explicitly.

**Fix (Gate A):**
- Updated `Themes/Colors.xaml` to the HF2 palette
- Added explicit `TargetType` styles in `App.xaml` for TextBlock, Label, RadioButton, TextBox, ComboBox/Item, ListBox/Item, ToolTip, ProgressBar
- Primary button uses dark-on-gold (`BrushOnAccent` on `BrushAccent`)
- Finding status colors: PASS green / FAIL red / WARN amber / UNKNOWN muted (never painted as FAIL)

### 2) SCAN appears to do nothing after entering server IP
**Root causes:**
1. Status text lived at the bottom of a left `StackPanel` and was easily clipped/obscured
2. `IsBusy` did not raise `PropertyChanged`, so command CanExecute / UI busy affordances stayed stale
3. Async `RelayCommand` did not reliably refresh CanExecute after scan start/end
4. No stage progress, elapsed time, or cancel — long deep scans looked hung
5. Always `DeepScan=true` with no Quick path

**Fix (Gates B/C/D/E/F/G):**
- Permanent status strip under connection controls (phase chip + status + stage + indeterminate progress + elapsed)
- `AsyncRelayCommand` + `IsBusy` PropertyChanged + cancel CTS
- Quick vs Deep scan wired through `DiagnosticOrchestrator`
- Server mode hides target IP; Client requires valid host before SCANNING
- Errors written to ProgramData (fallback LocalAppData/temp) with COPY ERROR DETAILS

## Safe Repair
Unchanged. Scan failure paths never invoke repair apply.

## Visual lab
`UI_VISUAL_LAB_NOT_RUN` — this cloud agent has no interactive Windows desktop. Screenshots deferred to Windows lab (`media/hf2/` when available).
