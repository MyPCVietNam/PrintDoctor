using System.IO.Compression;
using System.Text;
using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Services;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;
using MyPC.LanPrintDoctor.Abstractions.Smb;
using MyPC.LanPrintDoctor.Core.Compare;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Platform.Fakes;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;
using MyPC.LanPrintDoctor.Reports;

namespace MyPC.LanPrintDoctor.UnitTests;

/// <summary>
/// P1.1 regression suite — false-success repairs, hardcoded PASS/FAIL, empty.All compare,
/// evidence placeholders, PS status parsing, UNC/ShaPrint outcomes.
/// Gate labels: UNIT_PASS when green; WIN10/11/LAN/PRINT lab gates remain NOT_RUN.
/// </summary>
public class P11RegressionTests
{
    private readonly DecisionEngine _engine = new();

    [Fact]
    public async Task B01_NotImplementedRepair_NeverReportsSuccess()
    {
        var op = new NotImplementedRepair("FW-FAKE", "Fake");
        var exec = new RepairExecutor(new RepairJournal(TempDir("ni")));
        var result = await exec.ExecuteAsync(op, userConfirmed: true);
        Assert.True(result.NotImplemented);
        Assert.False(result.Applied);
        Assert.False(result.Verified);
        Assert.False(result.RolledBack);
        Assert.Equal(DiagnosticStatus.Blocked, result.Status);
        Assert.Contains("NOT_IMPLEMENTED", result.Message ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task B01_FirewallIcmp_RealApplyVerify_NoNoOpSuccess()
    {
        var fw = new FakeFirewallInspector();
        var elev = new FakeElevationService { IsAdmin = true };
        var op = new FirewallIcmpEchoRepair(fw, elev);
        Assert.True(op.IsImplemented);
        var exec = new RepairExecutor(new RepairJournal(TempDir("icmp")));
        var result = await exec.ExecuteAsync(op, userConfirmed: true);
        Assert.True(result.Applied);
        Assert.True(result.Verified);
        Assert.Equal(1, fw.IcmpEnableCalls);
        Assert.Contains(fw.Rules, r => (r.RuleId ?? "").Contains("FPS-ICMP4-ERQ-In"));
    }

    [Fact]
    public async Task B01_FilePrintShare_DoesNotMapToIcmp()
    {
        var fw = new FakeFirewallInspector();
        var elev = new FakeElevationService { IsAdmin = true };
        var op = new FilePrintShareRepair(fw, elev);
        Assert.Equal("FW-FILE-PRINT-SHARE", op.OperationId);
        Assert.NotEqual("FW-ICMP-ECHO", op.OperationId);
        var exec = new RepairExecutor(new RepairJournal(TempDir("fps")));
        var result = await exec.ExecuteAsync(op, userConfirmed: true);
        Assert.True(result.Applied);
        Assert.Equal(0, fw.IcmpEnableCalls);
        Assert.Equal(1, fw.SharingEnableCalls);
    }

    [Fact]
    public async Task B01_RolledBackFalse_WhenRollbackUnsupported()
    {
        var services = new FakeWindowsServiceInspector();
        services.Services["Spooler"] = new WindowsServiceInfo { Name = "Spooler", Status = "Stopped", StartType = "Automatic" };
        // Force verify fail after apply by clearing after start — use Scriptable instead:
        var op = new IrreversibleFailVerifyRepair();
        var exec = new RepairExecutor(new RepairJournal(TempDir("norb")));
        var result = await exec.ExecuteAsync(op, userConfirmed: true);
        Assert.True(result.Applied);
        Assert.False(result.Verified);
        Assert.False(result.RolledBack);
        Assert.True(result.RollbackUnsupported);
        Assert.Contains("irreversible", result.Message ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task B01_RollbackDoesNotUseCancelledToken()
    {
        CancellationToken? seen = null;
        var op = new TokenCaptureRepair(t => seen = t);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var exec = new RepairExecutor(new RepairJournal(TempDir("tok")));
        var result = await exec.ExecuteAsync(op, userConfirmed: true, cts.Token);
        // Apply may throw OperationCanceled; if backup existed rollback uses None.
        // TokenCaptureRepair backs up then throws on apply so rollback runs with None.
        Assert.NotNull(seen);
        Assert.False(seen!.Value.IsCancellationRequested);
        Assert.True(result.RolledBack || result.RollbackAttempted);
    }

    [Fact]
    public void B01_Journal_RecoversIncompleteApply()
    {
        var dir = TempDir("jrnl");
        var j1 = new RepairJournal(dir);
        j1.Record("OP", "Backup", true, backupId: "b1", backupPayload: "{}");
        j1.Record("OP", "Apply", true);
        var j2 = new RepairJournal(dir);
        var incomplete = j2.LoadIncomplete();
        Assert.Contains(incomplete, e => e.OperationId == "OP" && e.Phase == "Apply");
    }

    [Fact]
    public async Task B01_NetworkProfile_BlocksDomainManaged()
    {
        var elev = new FakeElevationService { IsAdmin = true };
        var profiles = new FakeNetworkProfileService
        {
            Profiles =
            {
                new NetworkConnectionProfile
                {
                    InterfaceIndex = 5,
                    Name = "Ethernet",
                    NetworkCategory = "DomainAuthenticated",
                    IsDomainManaged = true
                }
            }
        };
        var op = new NetworkProfilePrivateRepair(profiles, elev);
        var prereq = await op.CheckPrerequisitesAsync();
        Assert.False(prereq.CanProceed);
        Assert.Contains("Domain", prereq.Reason ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void B01_IcmpRule_MatchesVietnameseDisplayName()
    {
        var vi = new FirewallRuleInfo
        {
            Name = "FPS-ICMP4-ERQ-In",
            DisplayName = "Chia sẻ Tệp và Máy in (Yêu cầu Echo - ICMPv4-In)",
            RuleId = "FPS-ICMP4-ERQ-In",
            Enabled = true,
            Direction = "Inbound",
            Action = "Allow",
            Protocol = "ICMPv4",
            Profiles = "Private",
            RemoteAddresses = "LocalSubnet"
        };
        var en = new FirewallRuleInfo
        {
            Name = "File and Printer Sharing (Echo Request - ICMPv4-In)",
            DisplayName = "File and Printer Sharing (Echo Request - ICMPv4-In)",
            RuleId = "FPS-ICMP4-ERQ-In",
            Enabled = true,
            Direction = "Inbound",
            Action = "Allow",
            Protocol = "ICMPv4",
            Profiles = "Private",
            RemoteAddresses = "LocalSubnet"
        };
        Assert.True(FirewallIcmpEchoRepair.IsEnabledScopedIcmp(vi));
        Assert.True(FirewallIcmpEchoRepair.IsEnabledScopedIcmp(en));
        Assert.False(FirewallRuleScope.IsScopedIcmpEcho(new FirewallRuleInfo
        {
            Name = en.Name,
            RuleId = en.RuleId,
            Enabled = true,
            Direction = "Inbound",
            Action = "Allow",
            Protocol = "ICMPv4",
            Profiles = "Public",
            RemoteAddresses = "Any"
        }));
    }

    [Fact]
    public void B02_Tcp445Pass_UncNotTested_IsNotFalseFail()
    {
        var snap = Base();
        snap.SmbProbe = new SmbProbeResult
        {
            Target = "192.168.1.10",
            Tcp445 = ProbeOutcome.Pass,
            Tcp135 = ProbeOutcome.Pass,
            Unc = ProbeOutcome.NotTested,
            Detail = "UNC not attempted"
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "SMB-004A");
        Assert.DoesNotContain(f, x => x.Id == "SMB-004" && x.Status == DiagnosticStatus.Fail);
        Assert.Equal(DiagnosticStatus.Unknown, f.First(x => x.Id == "SMB-004A").Status);
    }

    [Fact]
    public void B02_UncAuthDenied()
    {
        var snap = Base();
        snap.SmbProbe = new SmbProbeResult
        {
            Target = "192.168.1.10",
            Tcp445 = ProbeOutcome.Pass,
            Unc = ProbeOutcome.AuthDenied,
            Detail = "ACCESS_DENIED"
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "SMB-004B");
    }

    [Fact]
    public void B02_ShaPrint_RunningAndListening_NoSha003()
    {
        var snap = Base();
        snap.ShaPrint = new ShaPrintInstallInfo
        {
            Installed = true,
            ProcessRunning = true,
            ListeningEndpoints = new[] { "0.0.0.0:48631" },
            ListeningCollectionStatus = ProbeOutcome.Pass
        };
        var f = _engine.Evaluate(snap);
        Assert.DoesNotContain(f, x => x.Id == "SHA-003");
    }

    [Fact]
    public void B02_ShaPrint_RunningButNotListening()
    {
        var snap = Base();
        snap.ShaPrint = new ShaPrintInstallInfo
        {
            Installed = true,
            ProcessRunning = true,
            ListeningEndpoints = Array.Empty<string>(),
            ListeningCollectionStatus = ProbeOutcome.Pass
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "SHA-003");
    }

    [Fact]
    public void B02_ShaPrint_NotInstalled()
    {
        var snap = Base();
        snap.ShaPrint = new ShaPrintInstallInfo { Installed = false, ListeningCollectionStatus = ProbeOutcome.Pass };
        var f = _engine.Evaluate(snap);
        Assert.DoesNotContain(f, x => x.Id is "SHA-002" or "SHA-003");
    }

    [Fact]
    public void B02_SharingDisabled_ReportsFailNotHardcodedPass()
    {
        var snap = Base();
        snap.SharingToggles = new SharingToggleState
        {
            NetworkDiscovery = ProbeOutcome.Fail,
            FileAndPrinterSharing = ProbeOutcome.Fail,
            Detail = "disabled"
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "SMB-005");
    }

    [Fact]
    public void B02_SharingUnknown_WhenCollectorLacksPermission()
    {
        var snap = Base();
        snap.SharingToggles = new SharingToggleState
        {
            NetworkDiscovery = ProbeOutcome.Unknown,
            FileAndPrinterSharing = ProbeOutcome.Unknown,
            Detail = "AccessDenied"
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "SMB-005U");
        Assert.Equal(DiagnosticStatus.Unknown, f.First(x => x.Id == "SMB-005U").Status);
    }

    [Fact]
    public void B02_ThirdPartyEmpty_WithUnknownStatus_DoesNotInventProducts()
    {
        var snap = Base();
        snap.ThirdPartySecurity = Array.Empty<ThirdPartySecurityProduct>();
        snap.ThirdPartyCollectionStatus = ProbeOutcome.Unknown;
        var f = _engine.Evaluate(snap);
        Assert.DoesNotContain(f, x => x.Id == "FW-003");
    }

    [Fact]
    public void B02_ShaPrintEndpoint_NotTested_IsUnknownNotFail()
    {
        var snap = Base();
        snap.ShaPrint = new ShaPrintInstallInfo
        {
            Installed = true,
            ProcessRunning = true,
            ListeningEndpoints = new[] { "0.0.0.0:48631" },
            ListeningCollectionStatus = ProbeOutcome.Pass
        };
        snap.ShaPrintConnectivity = new ShaPrintConnectivity
        {
            ServerEndpoint = ProbeOutcome.NotTested,
            DiscoveryPort = ProbeOutcome.NotTested
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "SHA-001U");
        Assert.DoesNotContain(f, x => x.Id == "SHA-001" && x.Status == DiagnosticStatus.Fail);
    }

    [Fact]
    public void H03_ProbeOutcome_NotTested_IsNotSuccess()
    {
        var p = new ConnectivityProbeResult
        {
            Target = "x",
            Protocol = ProbeProtocol.Icmp,
            Outcome = ProbeOutcome.NotTested
        };
        Assert.False(p.Success);
        Assert.Equal(DiagnosticStatus.Unknown, p.Status);
    }

    [Fact]
    public void H04_ServiceStatus_NumberAndString_NotConfused()
    {
        Assert.True(ServiceStatusParser.IsRunning("Running"));
        Assert.True(ServiceStatusParser.IsRunning("4"));
        Assert.False(ServiceStatusParser.IsRunning("Stopped"));
        Assert.False(ServiceStatusParser.IsRunning("1"));
        Assert.Equal("Running", ServiceStatusParser.Normalize("4"));
        Assert.Equal("Stopped", ServiceStatusParser.Normalize("1"));
        Assert.True(ServiceStatusParser.IsStopped("Stopped"));
        Assert.True(ServiceStatusParser.IsStopped("1"));
        Assert.False(ServiceStatusParser.IsStopped("Running"));
    }

    [Fact]
    public void H05_CompareEngine_EmptyProbes_NotCommonOutage()
    {
        var server = new DiagnosticSnapshot
        {
            SessionId = "S",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Server,
            SchemaVersion = "1.1.0",
            Adapters = new[]
            {
                new NetworkAdapterInfo
                {
                    Name = "Ethernet",
                    IsUp = true,
                    IPv4Addresses = new[] { "192.168.1.10" },
                    MacAddress = "AA:BB:CC:DD:EE:01",
                    DefaultGateway = "192.168.1.1"
                }
            }
        };
        var clients = Enumerable.Range(1, 4).Select(i => new DiagnosticSnapshot
        {
            SessionId = "C" + i,
            MachineName = "PC" + i,
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Client,
            SchemaVersion = "1.1.0",
            Adapters = new[]
            {
                new NetworkAdapterInfo { Name = "Ethernet", IsUp = true, IPv4Addresses = new[] { "192.168.1.2" + i }, DefaultGateway = "192.168.1.1" }
            },
            Probes = Array.Empty<ConnectivityProbeResult>() // empty.All() would be true — must NOT yield CMP-001
        }).ToList();

        var cmp = new CompareEngine().Compare(new CompareInput { Server = server, Clients = clients });
        Assert.DoesNotContain(cmp.Findings, f => f.Id == "CMP-001");
        Assert.NotEmpty(cmp.InsufficientEvidence);
    }

    [Fact]
    public void H05_CompareReports_ImportZipAndJson()
    {
        var root = TempDir("cmp");
        var serverPath = Path.Combine(root, "server.json");
        var clientPaths = new List<string>();
        File.WriteAllText(serverPath, SnapshotJson("S", MachineRole.Server, "192.168.1.10", probesOk: false));
        for (var i = 1; i <= 4; i++)
        {
            var p = Path.Combine(root, $"c{i}.json");
            File.WriteAllText(p, SnapshotJson("C" + i, MachineRole.Client, "192.168.1.10", probesOk: false, machine: "PC" + i));
            clientPaths.Add(p);
        }

        var zipPath = Path.Combine(root, "server.zip");
        using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            var e = zip.CreateEntry("Diagnostics.json");
            using var w = new StreamWriter(e.Open());
            w.Write(File.ReadAllText(serverPath));
        }

        var svc = new ReportCompareService();
        var fromJson = svc.CompareFiles(serverPath, clientPaths);
        Assert.Contains(fromJson.Findings, f => f.Id == "CMP-001");
        var fromZip = svc.CompareFiles(zipPath, clientPaths);
        Assert.Contains(fromZip.Findings, f => f.Id == "CMP-001");
        Assert.True(fromJson.HasValidEvidence);
    }

    [Fact]
    public void H05_Compare_RejectsBadSchema()
    {
        var root = TempDir("schema");
        var bad = Path.Combine(root, "bad.json");
        File.WriteAllText(bad, """{"sessionId":"x","startedAt":"2026-01-01T00:00:00Z","role":"Client","schemaVersion":"9.0.0"}""");
        var svc = new ReportCompareService();
        Assert.ThrowsAny<Exception>(() => svc.CompareFiles(bad, new[] { bad }));
    }

    [Fact]
    public async Task H06_ReportExporter_RedactsAndNoPlaceholderClaims()
    {
        var snap = new DiagnosticSnapshot
        {
            SessionId = "R1",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Client,
            MachineName = "SECRET-PC",
            TargetHost = "192.168.1.10",
            SchemaVersion = "1.1.0",
            Adapters = new[]
            {
                new NetworkAdapterInfo
                {
                    Name = "Ethernet",
                    IsUp = true,
                    MacAddress = "AA:BB:CC:DD:EE:FF",
                    IPv4Addresses = new[] { "192.168.1.20" },
                    DefaultGateway = "192.168.1.1",
                    Category = NetworkCategory.Private
                }
            },
            RepairsJson = """[{"OperationId":"FW-ICMP-ECHO","Phase":"Verify","Success":true}]""",
            BeforeAfterJson = """{"before":{"icmp":false},"after":{"icmp":true}}""",
            EventLogsText = "EventLogs: sample Microsoft-Windows-SMBClient"
        };
        snap.CollectorNotes.Add(new CollectorStatusNote { Collector = "Routes", Outcome = ProbeOutcome.Pass });
        snap.CollectorNotes.Add(new CollectorStatusNote { Collector = "Neighbors", Outcome = ProbeOutcome.Pass });
        var exporter = new ReportExporter { DefaultRoot = TempDir("rep") };
        var zip = await exporter.ExportZipAsync(snap, redact: true);
        Assert.True(File.Exists(zip));
        using var archive = ZipFile.OpenRead(zip);
        Assert.NotNull(archive.GetEntry("Diagnostics.json"));
        Assert.NotNull(archive.GetEntry("Repairs.json"));
        Assert.NotNull(archive.GetEntry("BeforeAfter.json"));
        Assert.NotNull(archive.GetEntry("EventLogs.txt"));
        Assert.NotNull(archive.GetEntry("SystemInfo.txt"));

        string Read(string name)
        {
            var e = archive.GetEntry(name)!;
            using var s = e.Open();
            using var r = new StreamReader(s);
            return r.ReadToEnd();
        }

        var diag = Read("Diagnostics.json");
            Assert.DoesNotContain("SECRET-PC", diag);
        Assert.DoesNotContain("AA:BB:CC:DD:EE:FF", diag, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("192.168.1.20", diag);
        var repairs = Read("Repairs.json");
        Assert.Contains("FW-ICMP-ECHO", repairs);
        Assert.DoesNotContain("placeholder", repairs, StringComparison.OrdinalIgnoreCase);
        var before = Read("BeforeAfter.json");
        Assert.Contains("icmp", before);
        Assert.DoesNotContain("\"placeholder\"", before, StringComparison.OrdinalIgnoreCase);
        var events = Read("EventLogs.txt");
        Assert.DoesNotContain("TODO", events);
        Assert.DoesNotContain("fake content", events, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProbeOutcome_Defaults_AreNotPass()
    {
        Assert.Equal(ProbeOutcome.NotTested, new SmbProbeResult { Target = "x" }.Tcp445);
        Assert.Equal(ProbeOutcome.NotTested, new SmbProbeResult { Target = "x" }.Unc);
        Assert.Equal(ProbeOutcome.NotTested, new ShaPrintConnectivity().ServerEndpoint);
        Assert.Equal(ProbeOutcome.NotTested, new ShaPrintConnectivity().DiscoveryPort);
        Assert.False(new ShaPrintConnectivity().ServerEndpointReachable);
    }

    private static DiagnosticSnapshot Base() => new()
    {
        SessionId = "T",
        StartedAt = DateTimeOffset.UtcNow,
        Role = MachineRole.Client,
        TargetHost = "192.168.1.10",
        SchemaVersion = "1.1.0",
        Adapters = new[]
        {
            new NetworkAdapterInfo
            {
                Name = "Ethernet",
                IsUp = true,
                Kind = AdapterKind.Ethernet,
                IPv4Addresses = new[] { "192.168.1.20" },
                PrefixLength = 24,
                DefaultGateway = "192.168.1.1",
                Category = NetworkCategory.Private
            }
        }
    };

    private static string SnapshotJson(string id, MachineRole role, string serverIp, bool probesOk, string? machine = null)
    {
        var probes = probesOk
            ? $@"[{{""target"":""{serverIp}"",""protocol"":""Icmp"",""outcome"":""Pass""}},{{""target"":""{serverIp}"",""protocol"":""Tcp"",""port"":445,""outcome"":""Pass""}}]"
            : $@"[{{""target"":""{serverIp}"",""protocol"":""Icmp"",""outcome"":""Fail""}},{{""target"":""{serverIp}"",""protocol"":""Tcp"",""port"":445,""outcome"":""Fail""}}]";
        var ip = role == MachineRole.Server ? serverIp : "192.168.1.50";
        return $@"{{
  ""sessionId"":""{id}"",
  ""machineName"":""{machine ?? id}"",
  ""startedAt"":""2026-11-01T00:00:00Z"",
  ""role"":""{role}"",
  ""schemaVersion"":""1.1.0"",
  ""adapters"":[{{""name"":""Ethernet"",""isUp"":true,""iPv4Addresses"":[""{ip}""],""macAddress"":""AA:BB:CC:DD:EE:01"",""defaultGateway"":""192.168.1.1""}}],
  ""services"":[{{""name"":""LanmanServer"",""status"":""Running""}}],
  ""probes"":{probes}
}}";
    }

    private static string TempDir(string tag)
    {
        var d = Path.Combine(Path.GetTempPath(), "lpd-p11-" + tag + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    private sealed class IrreversibleFailVerifyRepair : IRepairOperation
    {
        public string OperationId => "TEST-IRREV";
        public string Title => "Irreversible";
        public bool IsImplemented => true;
        public bool SupportsRollback => false;
        public RepairOwnerRole OwnerRole => RepairOwnerRole.LocalAny;
        public RepairTargetMachine TargetMachine => RepairTargetMachine.Local;

        public Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
            => Task.FromResult(new RepairPrerequisiteResult { CanProceed = true });

        public Task CollectEvidenceAsync(CancellationToken ct = default) => Task.CompletedTask;

        public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
            => Task.FromResult(new RepairPreview
            {
                OperationId = OperationId,
                Title = Title,
                Description = "irreversible test",
                Reversible = false
            });

        public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
            => Task.FromResult(new RepairBackup { BackupId = "b", Path = "j", CreatedAt = DateTimeOffset.UtcNow });

        public Task ApplyAsync(CancellationToken ct = default) => Task.CompletedTask;
        public Task<bool> VerifyAsync(CancellationToken ct = default) => Task.FromResult(false);

        public Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
            => Task.FromResult(new RollbackResult { Attempted = false, Unsupported = true, Message = "irreversible" });
    }

    private sealed class TokenCaptureRepair : IRepairOperation
    {
        private readonly Action<CancellationToken> _onRollback;

        public TokenCaptureRepair(Action<CancellationToken> onRollback) => _onRollback = onRollback;

        public string OperationId => "TEST-TOKEN";
        public string Title => "Token";
        public bool IsImplemented => true;
        public bool SupportsRollback => true;
        public RepairOwnerRole OwnerRole => RepairOwnerRole.LocalAny;
        public RepairTargetMachine TargetMachine => RepairTargetMachine.Local;

        public Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
            => Task.FromResult(new RepairPrerequisiteResult { CanProceed = true });

        public Task CollectEvidenceAsync(CancellationToken ct = default) => Task.CompletedTask;

        public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
            => Task.FromResult(new RepairPreview
            {
                OperationId = OperationId,
                Title = Title,
                Description = "t",
                Reversible = true
            });

        public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
            => Task.FromResult(new RepairBackup { BackupId = "b", Path = "j", CreatedAt = DateTimeOffset.UtcNow, PayloadJson = "{}" });

        public Task ApplyAsync(CancellationToken ct = default)
            => throw new InvalidOperationException("force rollback");

        public Task<bool> VerifyAsync(CancellationToken ct = default) => Task.FromResult(true);

        public Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default)
        {
            _onRollback(ct);
            return Task.FromResult(new RollbackResult { Attempted = true, Succeeded = true, Verified = true });
        }
    }
}
