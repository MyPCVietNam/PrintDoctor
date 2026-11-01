# AUDIT REPORT — MyPC LAN & Print Doctor v1.0

## Identity

- Repository: https://github.com/MyPCVietNam/PrintDoctor
- Branch: `feat/lan-print-doctor-v1`
- Product: MyPC LAN & Print Doctor v1.0
- Framework: .NET 10 / WPF win-x64 self-contained

## Build & tests (this Cloud agent)

| Gate | Result |
|------|--------|
| `dotnet build` Release (Linux + EnableWindowsTargeting) | PASS |
| Unit tests (35) | PASS |
| Integration tests safe/isolated (4) | PASS |
| Windows GitHub Actions CI | See Actions run URL after push |
| Windows 10 22H2 lab | **NOT_RUN / BLOCKED** |
| Windows 11 24H2/25H2/26H2 lab | **NOT_RUN / BLOCKED** |
| Physical printer / USB / RAW 9100 print | **NOT_RUN / BLOCKED** |
| Production network reset tests | **NOT_RUN** (by design — not approved) |

## Safety posture

- Default scan is read-only
- No firewall disable / SMB1 enable / insecure guest / SMB signing disable
- Repair requires confirmation + admin; backup/verify/rollback journaled
- Host input validated against injection before probes/process args

## Known gaps

- Some Windows enrichers (full UNC auth, Network List Manager category, neighbor cache via PowerShell) are best-effort on first release; core TCP/ICMP/adapter/decision path is implemented
- Compare UI imports JSON/ZIP manually via engine; deeper import wizard can iterate
- Firewall ICMP apply hook is preview-capable; service start repairs are live via PowerShell when elevated on Windows

## Artifacts expected

1. MyPC-PrintDoctor-FULL-SOURCE.zip
2. MyPC-PrintDoctor-CHANGED-SOURCE.zip
3. MyPC-PrintDoctor-RELEASE-x64.zip (from Windows CI publish)
4. SHA256 + TEST-SUMMARY from CI
