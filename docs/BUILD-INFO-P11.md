# BUILD-INFO — P1.1

- Product: MyPC LAN & Print Doctor
- Version: 1.1.0
- Baseline: `1647875` (PR #1 merge)
- Branch: `fix/p11-diagnostic-accuracy-safe-repair`
- Target frameworks: `net10.0` (libs/tests), `net10.0-windows` (WPF)
- RID: `win-x64`
- Self-contained: `true`
- PublishSingleFile: `false` → **self-contained multi-file** release (primary EXE + .NET runtime files). Do not claim a single independent EXE.
- CI: `.github/workflows/windows-build.yml` (push on `main`, `feat/**`, `fix/**`, `cursor/**`)
