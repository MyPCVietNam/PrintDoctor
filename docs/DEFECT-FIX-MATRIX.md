# DEFECT-FIX-MATRIX — P1.1 + HF1

Baseline: PR #1 merged commit `1647875`. Branch: `fix/p11-diagnostic-accuracy-safe-repair` (PR #2).
HF1 audit HEAD: `6c753e1`.

## HF1 defects

| Defect ID | Severity | Status | Root cause | File/function | Before | After | Test ID | Test result | Remaining risk |
|-----------|----------|--------|------------|---------------|--------|-------|---------|-------------|----------------|
| HF1-B01 | BLOCKER | FIXED | Group enable widened Public/Domain; enable-before-scope | `PowerShellWindowsInspectors.Enable*`, `FirewallRuleScope`, `*Repair.VerifyAsync` | Group enable / Enabled-only verify | Per-rule Private+LocalSubnet before Enable; strict Verify; skip GPO | HF1_01, HF1_04 | UNIT_PASS | Live Win firewall SKU variance |
| HF1-B02 | BLOCKER | FIXED | Rollback trusted PS OK; no TransactionId; Apply not durable pre-mutation | `RepairJournal`, `RepairExecutor`, `Restore*FromBackupAsync` | False RollbackVerified | Re-read compare; ApplyStarted; UNCERTAIN_STATE; tx id | HF1_02, HF1_07, HF1_08 | UNIT_PASS | Manual operator resume UI |
| HF1-H03 | HIGH | FIXED | `!p.Success` treated Unknown as Fail | `DecisionEngine.EvaluateNetwork` | False LAN-001 | Decisive Pass/Fail only | HF1_05* | UNIT_PASS | — |
| HF1-H04 | HIGH | FIXED | Client repaired server ICMP inbound | `Finding.RepairOwner`, `RepairExecutor`, `MainViewModel` | Local FW-ICMP on client | SERVER_ACTION_REQUIRED | HF1_06 | UNIT_PASS | No remote admin by design |
| HF1-H05 | HIGH | FIXED | Partial redaction / ACL skip | `ReportExporter` | IP/MAC leaks | Stable tokens all files; ACL on ZIP | HF1_09 | UNIT_PASS | Token compare limits noted |
| HF1-H06 | HIGH | FIXED | Guest from server cfg; foreign PID; weak schema | SMB/ShaPrint collectors, `ReportCompareService` | Mis-attribution | Client guest cfg; PID filter; schema/size checks | HF1_10, HF1_11 | UNIT_PASS | Lab PID name variants |
| HF1-H07 | HIGH | FIXED | Fake RELEASE ZIP on publish fail | `package-p11-artifacts.sh` | Misleading zip | RELEASE_BLOCKED only | HF1_12 | UNIT_PASS | Authoritative RELEASE from Windows CI |

## P1.1 defects (prior)

Baseline: PR #1 merged commit `1647875`. Branch: `fix/p11-diagnostic-accuracy-safe-repair`.

| Defect ID | Severity | Root cause | File/function | Before | After | Test ID | Test result | Remaining risk |
|-----------|----------|------------|---------------|--------|-------|---------|-------------|----------------|
| B01-FAKE-SUCCESS | BLOCKER | `FirewallIcmpEchoRepair` / `NetworkProfilePrivateRepair` accepted no-op `Apply`/`Verify=true`; `MainViewModel` constructed them without real deps | `Repair/Operations/*`, `MainViewModel.CreateRepair`, `RepairExecutor` | Repair reported Pass with zero system change | Real Apply/Verify/Backup/Rollback wired; `NotImplementedRepair` blocks unknown ids; `IsImplemented=false` never Pass | `B01_NotImplementedRepair_NeverReportsSuccess`, `B01_FirewallIcmp_RealApplyVerify_NoNoOpSuccess`, Scenario15–17 | UNIT_PASS | Windows lab must confirm netsh/Firewall cmdlets under UAC |
| B01-FPS-MAP | BLOCKER | `FW-FILE-PRINT-SHARE` mapped to ICMP repair | `MainViewModel`, `FilePrintShareRepair` | Wrong rule group enabled | Dedicated FPS group `@FirewallAPI.dll,-28502` repair | `B01_FilePrintShare_DoesNotMapToIcmp` | UNIT_PASS | VI localization of group id relies on well-known resource id |
| B01-ROLLBACK-LIE | BLOCKER | `RolledBack=true` without verified rollback; cancelled token reused | `RepairExecutor.SafeRollbackAsync` | False rollback success | `RolledBack` only when Succeeded∧Verified; rollback uses `CancellationToken.None`; unsupported flagged | `B01_RolledBackFalse_WhenRollbackUnsupported`, `B01_RollbackDoesNotUseCancelledToken` | UNIT_PASS | Crash mid-Apply still needs operator review of journal |
| B01-JOURNAL | HIGH | Journal not crash-recoverable | `RepairJournal.LoadIncomplete` | In-memory only / weak persist | Durable JSON + incomplete Apply detection | `B01_Journal_RecoversIncompleteApply` | UNIT_PASS | Manual resume UI not yet exposed |
| B01-PROFILE-POLICY | HIGH | Profile repair no-op / ignored domain | `NetworkProfilePrivateRepair` | Always “success” | Reads real profiles; blocks DomainAuthenticated / policy | `B01_NetworkProfile_BlocksDomainManaged` | UNIT_PASS | GPO edge cases need Win domain lab |
| B02-UNC-HARDCODE | BLOCKER | `UncReachable` hard-coded false | `PowerShellWindowsInspectors.ProbeRemoteAsync` | Always Fail UNC | Real `Test-Path \\host\IPC$` → Pass/Fail/AuthDenied/Unknown/NotTested | `B02_Tcp445Pass_UncNotTested_*`, `B02_UncAuthDenied` | UNIT_PASS | Auth prompts on locked-down hosts |
| B02-SHARING-TRUE | BLOCKER | Sharing toggles always true/true | `GetSharingTogglesAsync` | Hard Pass | Firewall group enablement counts → Pass/Fail/Unknown | `B02_SharingDisabled_*`, `B02_SharingUnknown_*` | UNIT_PASS | Group resource ids must exist on SKU |
| B02-SHAPRINT-LISTEN | BLOCKER | ListeningEndpoints always empty | `PowerShellPrinterAndShaPrint` | False SHA-003 | `Get-NetTCPConnection` / UDP endpoints + collection status | `B02_ShaPrint_*` | UNIT_PASS | Needs ShaPrint installed lab |
| B02-3RDPARTY | BLOCKER | ThirdParty always empty array as Pass | `DetectThirdPartySecurityAsync` | Silent empty | WMI SecurityCenter2 + `ProbeOutcome` Unknown on failure | `B02_ThirdPartyEmpty_*` | UNIT_PASS | Some SKUs lack SecurityCenter2 |
| B02-DISCOVERY | MEDIUM | DiscoveryPortOpen hard false | ShaPrint connectivity | Always Fail | Probe UDP 48633 → Pass/Fail/NotTested/Unknown | `B02_ShaPrintEndpoint_NotTested_*` | UNIT_PASS | UDP probe is best-effort |
| H03-ROUTES-EMPTY | HIGH | Routes/Neighbors empty; Category Unknown; Metric=InterfaceIndex | `WindowsNetworkProbe` | Empty/wrong | Get-NetRoute/Neighbor/ConnectionProfile/IPInterface | Covered by collector code + notes; lab WIN*_NOT_RUN | UNIT_PASS (logic); WIN10/11_LAB_NOT_RUN | Must validate on physical NICs |
| H04-PS-JSON | HIGH | Status enum number/string confusion | `PowerShellJson`, `ServiceStatusParser` | Running could be misread | Normalize `4`/`Running`, VI/EN truthy | `H04_ServiceStatus_NumberAndString_NotConfused` | UNIT_PASS | Full PS 5.1 matrix on Win10/11 lab still NOT_RUN |
| H04-FW-RULES | HIGH | Firewall matched DisplayName EN only | `GetRelevantRulesAsync`, `IsEnabledScopedIcmp` | Missed VI rules | Protocol/port/address filters + VI Echo strings | `B01_IcmpRule_MatchesVietnameseDisplayName` | UNIT_PASS | Custom third-party rule names |
| H05-EMPTY-ALL | HIGH | `Enumerable.All` on empty probes → false CMP-001 | `CompareEngine` | Fake common outage | Require non-empty valid probe sets; insufficient evidence otherwise | `H05_CompareEngine_EmptyProbes_NotCommonOutage`, Scenario25 | UNIT_PASS | — |
| H05-COMPARE-UI | HIGH | Compare button non-functional / fake | `MainViewModel.CompareReports`, `ReportCompareService` | No import | ZIP/JSON import, schema check, real correlation | `H05_CompareReports_ImportZipAndJson`, `H05_Compare_RejectsBadSchema` | UNIT_PASS | UX multi-select >4 OK; large ZIPs untested |
| H06-EVIDENCE | HIGH | Redaction/ACL/repairs placeholders | `ReportExporter` | Fake sections | Real journal/before-after/event collector; JSON redaction; ACL on Windows | `H06_ReportExporter_RedactsAndNoPlaceholderClaims` | UNIT_PASS | ACL/`Get-WinEvent` need Windows CI/lab |

## Security posture (unchanged guarantees)

- Never suggest disable firewall / enable SMB1 / disable SMB signing / enable insecure guest.
- Repair surface excludes winsock/ip reset.
- Firewall repair scoped Private + LocalSubnet only.
