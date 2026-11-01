# BUILD-INFO — P1.1 HF final two safety defects

- Product: MyPC LAN & Print Doctor
- Version: **1.1.4**
- Baseline (HF final two): `8cf484590614dc4ddb363866074f944af212dd1a`
- Prior correction baseline: `a33d201841049523b801e9d31950532684ef6cbd`
- Branch: `fix/p11-diagnostic-accuracy-safe-repair` (PR #2)
- Target frameworks: `net10.0` (libs/tests), `net10.0-windows` (WPF)
- RID: `win-x64`
- Self-contained: `true`
- PublishSingleFile: `false` → **self-contained multi-file** release
- CI: `.github/workflows/windows-build.yml` (no production firewall mutation)
- FIELD READY: **false** (Windows physical / read-only lab still required)
