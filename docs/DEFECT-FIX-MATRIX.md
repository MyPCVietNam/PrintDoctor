# DEFECT-FIX-MATRIX — P1.1 + HF1 + HF2 + corrections + P2 RC1

Baseline: PR #1 `1647875`. PR #2 branch `fix/p11-diagnostic-accuracy-safe-repair`.
Final-two baseline HEAD: `8cf4845` → `0962972`.
P2 branch: `cursor/p2-rc1-field-pilot-e81e` from `0962972`. Version **1.2.0-RC1**.

## P2 Field Pilot (v1.2.0-RC1)

| Defect ID | Severity | Status | File/function | After | Test | Result | Remaining risk |
|-----------|----------|--------|---------------|-------|------|--------|----------------|
| P2-00-A Invalid Set-AddressFilter | BLOCKER | FIXED | `PowerShellWindowsInspectors`, `NetSecurityCommandCatalog`, owned repairs | Mutations use `Set-NetFirewallRule -RemoteAddress`; catalog forbids Set+Associated | P2_00A_* + live Win binding probe | UNIT_PASS; Win binding on CI | — |
| P2-00-B Enabled False truthy | BLOCKER | FIXED | `PowerShellJson.TryParseEnabled` | `"False"` never truthy; unknown ⇒ not enabled | P2_00B_* | UNIT_PASS | Full PS 5.1 enum matrix lab |
| P2-00-C Durable journal | BLOCKER | FIXED | `RepairJournal.RecordMutationIntent`, WriteThrough Persist | Intent before Apply; corrupt fail-closed; UNCERTAIN on crash | P2_00C_* | UNIT_PASS | Operator resume UX |
| P2-01 Root-cause CASE A/B/C | HIGH | FIXED | `NetworkRootCauseEngine` | Evidence-based; INFRASTRUCTURE_ACTION_REQUIRED | P2_01_* | UNIT_PASS | Physical LAN NOT_RUN |
| P2-02 Owned firewall | HIGH | FIXED | `OwnedFirewallRuleRepair` | MyPC.PrintDoctor.* Disabled→verify→Enable; no 48632 LAN | P2_02_* | UNIT_PASS | Live Win mutation lab BLOCKED |
| P2-UI Multi-repair pick | HIGH | FIXED | `MainViewModel.SafeRepairAsync` | User must choose; no auto-first | Manual + code review | CODE | Field UX |

FIELD_VALIDATION_PENDING. WIN10/11 physical lab **NOT_RUN**. Not FIELD/PRODUCTION READY.

## Final two safety defects (v1.1.4)

| Defect ID | Severity | Status | File/function | After | Test | Result | Remaining risk |
|-----------|----------|--------|---------------|-------|------|--------|----------------|
| D1 Mutation-before-track | BLOCKER | FIXED (code+unit+PS fixture) | `EnableScopedIcmpEchoAsync`, `EnableFileAndPrinterSharingAsync` | Snapshot+`$tracked` before first Set-*; controlled Restore-RuleSnap; UNCERTAIN on ROLLBACK_FAIL | D1_* | UNIT_PASS | Live Win mutation lab **BLOCKED** |
| D2 Empty journal fail-open | BLOCKER | FIXED (code+unit) | `RepairJournal.LoadFile` | empty/whitespace file ⇒ CorruptJournal; no overwrite; executor BLOCKED | D2_* | UNIT_PASS | — |

## HF2 final correction

| Defect ID | Severity | Status | File/function | After | Test | Result | Remaining risk |
|-----------|----------|--------|---------------|-------|------|--------|----------------|
| HF2C-Journal Success | BLOCKER | FIXED (code+unit) | `RepairJournal.IsUncertain` | Phase∧Success; Verify/RollbackVerified false ⇒ UNCERTAIN | HF2C_VerifyFalse_*, HF2C_Applied_RollbackFailed_* | UNIT_PASS | — |
| HF2C-Corrupt | BLOCKER | FIXED (code+unit) | `RepairJournal.LoadFile`, `CorruptJournal` | Unreadable JSON ⇒ CORRUPT_JOURNAL never Clean | HF2C_CorruptJournal_* | UNIT_PASS | — |
| HF2C-Executor block | BLOCKER | FIXED (code+unit) | `RepairExecutor.ExecuteAsync` | UNCERTAIN/INCOMPLETE/CORRUPT ⇒ BLOCKED before Apply | HF2C_Executor_* | UNIT_PASS | — |
| HF2C-Rollback scope | BLOCKER | FIXED (code+unit) | `*Repair.RollbackAsync`, `PARTIAL_CHANGED` PS | Only transaction ChangedRuleIds restored | HF2C_Rollback_OnlyTouches*, HF2C_PsFixture_PartialChanged* | UNIT_PASS | Live Win restore lab **BLOCKED** |
| HF2C-Collector UNKNOWN | HIGH | FIXED (code+unit) | DecisionEngine / collectors | PS fail ⇒ UNKNOWN not fake PASS | HF2C_PowerShellCollectorFail_* | UNIT_PASS | Read-only Win lab **BLOCKED** |

## HF2 defects

| Defect ID | Severity | Status | File/function | After | Test | Result | Remaining risk |
|-----------|----------|--------|---------------|-------|------|--------|----------------|
| HF2-A Scope | BLOCKER | FIXED (code+unit+PS fixture) | `EnableFileAndPrinterSharingAsync`, `EnableScopedIcmpEchoAsync`, `FirewallRuleScope`, repair Verify | No empty catch; scope before Enable; all changed ids verified; empty remote ≠ LocalSubnet | HF2_RemoteAddressFail_*, HF2_OneGoodOneBad*, HF2_EmptyRemote*, Hf2WindowsPowerShellFixtureTests | UNIT+INT_PASS (no CI mutation) | Win10/11 live firewall mutation lab **BLOCKED** |
| HF2-B Rollback | BLOCKER | FIXED (code+unit) | `Restore*FromBackupAsync`, `MatchesBackupSnapshot` | PARTIAL_ROLLBACK if RemoteAddress mismatch | HF2_RollbackWrongRemote* | UNIT_PASS | Live restore lab **BLOCKED** |
| HF2-C Crash | BLOCKER | FIXED (code+unit) | `RepairJournal.IsUncertain`, `ScanAllSessions`, MainViewModel | Applied w/o Verify + cross-session block | HF2_CrashAfterApplied*, HF2_RecoveryFromPrior* | UNIT_PASS | Operator UX manual only |
| HF2-D NIC | HIGH | FIXED (code+unit) | `NetworkProfilePrivateRepair`, MainViewModel | Explicit IfIndex; Preview details | HF2_MultiNic* | UNIT_PASS | UI selection UX |
| HF2-E Privacy | HIGH | FIXED (code+unit) | `ReportExporter.StableToken` | Ephemeral HMAC, key not in ZIP | HF2_Redaction_NotReversible* | UNIT_PASS | — |
| HF2-F ShaPrint | HIGH | FIXED (code+unit) | `CollectListeningAsync` | ShaPrint path/PID only; FOREIGN_PROCESS | HF2_PrintBridge* | UNIT_PASS | Live process names lab |
| HF2-G Client role | HIGH | FIXED | `ReportCompareService` | Client role required | HF2_ClientReport_WrongRole* | UNIT_PASS | — |

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
