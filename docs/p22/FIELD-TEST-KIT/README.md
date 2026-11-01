# Field Test Kit — v1.2.2-RC3

1. Install Windows RELEASE ZIP from CI artifacts (multi-file self-contained).
2. On **server**: run `MyPC.LanPrintDoctor.exe` → Server → SCAN → Export BEFORE.
3. On **one client**: Client mode → server IPv4 → SCAN → Export BEFORE.
4. Compare reports in-app.
5. Apply at most one eligible repair with consent; expect LOCAL_CONFIG_VERIFIED only.
6. See `docs/FIELD-TEST-CHECKLIST-P22.md` for full checklist and disabled ops.
7. Read-only fallback: SCAN + Export without Safe Repair.

Rollback: journal under `%ProgramData%\MyPC\LanPrintDoctor` / session journals; unfinished transactions block further Apply until technician review.
