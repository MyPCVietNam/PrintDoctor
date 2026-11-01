# FINAL DELIVERY — MyPC LAN & Print Doctor v1.0

## Repository

- URL: https://github.com/MyPCVietNam/PrintDoctor
- Branch: `feat/lan-print-doctor-v1`
- Commit: `09b15b36d8e794189eb9a9370eb6fa7578b34e49`
- Pull Request: https://github.com/MyPCVietNam/PrintDoctor/pull/1

## GitHub Actions

- Push run (SUCCESS): https://github.com/MyPCVietNam/PrintDoctor/actions/runs/41304978177
- PR run (SUCCESS): https://github.com/MyPCVietNam/PrintDoctor/actions/runs/41304998563
- Build: Release win-x64 self-contained — PASS
- Unit tests: 35/35 PASS
- Integration tests (safe): 4/4 PASS

## Artifacts

| Artifact | Path |
|----------|------|
| FULL SOURCE ZIP | `artifacts/delivery/MyPC-PrintDoctor-FULL-SOURCE.zip` |
| CHANGED SOURCE ZIP | `artifacts/delivery/MyPC-PrintDoctor-CHANGED-SOURCE.zip` |
| RELEASE ZIP | `artifacts/delivery/MyPC-PrintDoctor-RELEASE-x64.zip` |
| EXE (inside publish/CI) | `MyPC.LanPrintDoctor.exe` in RELEASE ZIP / Actions artifact `publish/win-x64/` |
| SHA256 | `artifacts/delivery/DELIVERY-SHA256.txt` |
| Test summary | `artifacts/delivery/TEST-SUMMARY.md` |

Also mirrored under `/opt/cursor/artifacts/`.

CI artifact download: Actions run → `MyPC-PrintDoctor-windows-x64`.

## How to run

1. Unpack `MyPC-PrintDoctor-RELEASE-x64.zip` on Windows 10/11 x64 (no .NET install required).
2. Run `MyPC.LanPrintDoctor.exe`.
3. Server: role Máy chủ → KIỂM TRA → XUẤT BÁO CÁO.
4. Client: role Máy trạm + IP server → KIỂM TRA → XUẤT BÁO CÁO.
5. Safe repair only after causes + confirmation + UAC when required.

## BLOCKED / NOT_RUN gates

- Windows 10 22H2 physical lab
- Windows 11 24H2 / 25H2 / 26H2 physical lab
- Physical printer / USB / live ShaPrint multi-day outage reproduction
- Destructive network reset tests (intentionally not run)

**Not claimed:** PRODUCTION READY based solely on Windows CI.
