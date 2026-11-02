using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Printing;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Services;
using MyPC.LanPrintDoctor.Abstractions.ShaPrint;
using MyPC.LanPrintDoctor.Abstractions.Smb;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Core.Orchestration;
using MyPC.LanPrintDoctor.Platform.Fakes;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;

namespace MyPC.LanPrintDoctor.UnitTests;

public class DecisionEngineScenarioTests
{
    private readonly DecisionEngine _engine = new();

    private static NetworkAdapterInfo LanAdapter(string ip = "192.168.1.20", int prefix = 24, NetworkCategory cat = NetworkCategory.Private)
        => new()
        {
            Name = "Ethernet",
            IsUp = true,
            Kind = AdapterKind.Ethernet,
            IPv4Addresses = new[] { ip },
            PrefixLength = prefix,
            SubnetMask = IpMath.PrefixToMask(prefix),
            DefaultGateway = "192.168.1.1",
            MacAddress = "AA:BB:CC:DD:EE:01",
            Category = cat
        };

    [Fact]
    public void Scenario1_IcmpFail_TcpPass_SuspectsIcmpBlock()
    {
        var snap = BaseClient("192.168.1.10");
        snap.Probes = new[]
        {
            FailIcmp("192.168.1.10"),
            OkTcp("192.168.1.10", 445)
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "LAN-002");
        Assert.DoesNotContain(f, x => x.Id == "LAN-001");
    }

    [Fact]
    public void Scenario2_IcmpAndTcpFail_Unreachable()
    {
        var snap = BaseClient("192.168.1.10");
        snap.Probes = new[] { FailIcmp("192.168.1.10"), FailTcp("192.168.1.10", 445), FailTcp("192.168.1.10", 135) };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "LAN-001");
    }

    [Fact]
    public void Scenario3_WrongSubnet()
    {
        var snap = BaseClient("10.0.0.5");
        snap.Adapters = new[] { LanAdapter("192.168.1.20", 24) };
        snap.Probes = new[] { FailIcmp("10.0.0.5"), FailTcp("10.0.0.5", 445) };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "LAN-003");
    }

    [Fact]
    public void Scenario4_WrongGateway()
    {
        var snap = BaseClient("192.168.1.10");
        snap.Adapters = new[] { LanAdapter() };
        snap.Probes = new[] { FailIcmp("192.168.1.1"), FailIcmp("192.168.1.10"), FailTcp("192.168.1.10", 445) };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "LAN-004");
    }

    [Fact]
    public void Scenario5_IpConflictSoftSignal()
    {
        var snap = BaseClient("192.168.1.10");
        snap.Neighbors = new[]
        {
            new NeighborEntry { IpAddress = "192.168.1.10", MacAddress = "AA:AA:AA:AA:AA:01" },
            new NeighborEntry { IpAddress = "192.168.1.10", MacAddress = "BB:BB:BB:BB:BB:02" }
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "LAN-007");
        Assert.True(f.First(x => x.Id == "LAN-007").Confidence < 0.9);
    }

    [Fact]
    public void Scenario6_PublicProfile()
    {
        var snap = BaseClient(null);
        snap.Role = MachineRole.Server;
        snap.Adapters = new[] { LanAdapter(cat: NetworkCategory.Public) };
        snap.FirewallProfiles = new[]
        {
            new FirewallProfileState { Profile = FirewallProfileKind.Public, Enabled = true }
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "FW-001");
        Assert.Equal("NET-PROFILE-PRIVATE", f.First(x => x.Id == "FW-001").RepairId);
    }

    [Fact]
    public void Scenario7_SmbServiceStopped()
    {
        var snap = BaseClient(null);
        snap.Role = MachineRole.Server;
        snap.Services = new[] { new WindowsServiceInfo { Name = "LanmanServer", Status = "Stopped", StartType = "Automatic" } };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "SMB-002");
    }

    [Fact]
    public void Scenario8_SpoolerStopped()
    {
        var snap = BaseClient(null);
        snap.Services = new[] { new WindowsServiceInfo { Name = "Spooler", Status = "Stopped" } };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "PRN-001");
    }

    [Fact]
    public void Scenario9_PrinterOffline()
    {
        var snap = BaseClient(null);
        snap.Role = MachineRole.Server;
        snap.Printers = new[] { new PrinterInfo { Name = "Office-HP", Offline = true, PortName = "USB001" } };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "PRN-003");
    }

    [Fact]
    public void Scenario10_ShaPrintProcessStopped()
    {
        var snap = BaseClient("192.168.1.10");
        snap.ShaPrint = new ShaPrintInstallInfo { Installed = true, ProcessRunning = false, InstallPath = @"C:\Program Files\ShaPrint" };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "SHA-002");
    }

    [Fact]
    public void Scenario11_ShaPrintNotListening()
    {
        var snap = BaseClient("192.168.1.10");
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
    public void Scenario12_ShaPrintEndpointUnavailable()
    {
        var snap = BaseClient("192.168.1.10");
        snap.ShaPrint = new ShaPrintInstallInfo { Installed = true, ProcessRunning = true, ListeningEndpoints = new[] { "0.0.0.0:48631" } };
        snap.ShaPrintConnectivity = new ShaPrintConnectivity { ServerEndpoint = ProbeOutcome.Fail, Detail = "filtered" };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "SHA-001");
    }

    [Fact]
    public void Scenario13_DoesNotSendRawToPrinter()
    {
        Assert.Null(typeof(IPrinterInspector).GetMethod("SendRaw"));
    }

    [Fact]
    public void Scenario14_ServerNoPrinters()
    {
        var snap = BaseClient(null);
        snap.Role = MachineRole.Server;
        snap.Printers = Array.Empty<PrinterInfo>();
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "PRN-002");
    }

    [Fact]
    public async Task Scenario15_RepairBlockedWithoutAdmin()
    {
        var elev = new FakeElevationService { IsAdmin = false };
        var op = new FirewallIcmpEchoRepair(new FakeFirewallInspector(), elev);
        var prereq = await op.CheckPrerequisitesAsync();
        Assert.False(prereq.CanProceed);
        Assert.True(prereq.RequiresAdmin);
    }

    [Fact]
    public async Task Scenario16_RepairFailsMidway_RollsBack()
    {
        var rolled = false;
        var applied = false;
        var op = new ScriptableRepair(
            apply: _ => { applied = true; throw new InvalidOperationException("mid-fail"); },
            verify: _ => Task.FromResult(true),
            rollback: (_, _) =>
            {
                rolled = true;
                return Task.FromResult(new RollbackResult { Attempted = true, Succeeded = true, Verified = true });
            });
        var journal = new RepairJournal(Path.Combine(Path.GetTempPath(), "lpd-ut-" + Guid.NewGuid().ToString("N")));
        var exec = new RepairExecutor(journal, journal.DirectoryPath);
        var result = await exec.ExecuteAsync(op, userConfirmed: true);
        Assert.True(applied);
        Assert.True(rolled);
        Assert.True(result.RolledBack);
        Assert.Equal(DiagnosticStatus.Fail, result.Status);
    }

    [Fact]
    public async Task Scenario17_RollbackAfterFailedVerify()
    {
        var rolled = false;
        var op = new ScriptableRepair(
            apply: _ => Task.CompletedTask,
            verify: _ => Task.FromResult(false),
            rollback: (_, _) =>
            {
                rolled = true;
                return Task.FromResult(new RollbackResult { Attempted = true, Succeeded = true, Verified = true });
            });
        var journal = new RepairJournal(Path.Combine(Path.GetTempPath(), "lpd-ut-" + Guid.NewGuid().ToString("N")));
        var exec = new RepairExecutor(journal, journal.DirectoryPath);
        var result = await exec.ExecuteAsync(op, userConfirmed: true);
        Assert.True(rolled);
        Assert.False(result.Verified);
        Assert.True(result.RolledBack);
    }

    [Fact]
    public void Scenario18_LossOfConnectivityStillEmitsUnreachable()
    {
        var snap = BaseClient("192.168.1.10");
        snap.Probes = new[] { FailIcmp("192.168.1.10"), FailTcp("192.168.1.10", 445) };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "LAN-001");
    }

    [Fact]
    public void Scenario19_FirewallGpoBlocked()
    {
        var snap = BaseClient(null);
        snap.FirewallProfiles = new[]
        {
            new FirewallProfileState { Profile = FirewallProfileKind.Domain, Enabled = true, ManagedByPolicy = true }
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "FW-002" && x.Status == DiagnosticStatus.Blocked);
    }

    [Fact]
    public void Scenario20_ThirdPartyFirewall()
    {
        var snap = BaseClient(null);
        snap.ThirdPartySecurity = new[] { new ThirdPartySecurityProduct { Name = "VendorFW" } };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "FW-003");
    }

    [Fact]
    public void Scenario21_MultipleAdapters()
    {
        var snap = BaseClient("192.168.1.10");
        snap.Adapters = new[]
        {
            LanAdapter("192.168.1.20"),
            new NetworkAdapterInfo { Name = "Wi-Fi", IsUp = true, Kind = AdapterKind.WiFi, IPv4Addresses = new[] { "192.168.1.21" }, PrefixLength = 24 }
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "LAN-005");
    }

    [Fact]
    public void Scenario22_VpnAdapter()
    {
        var snap = BaseClient("192.168.1.10");
        snap.Adapters = new[]
        {
            LanAdapter(),
            new NetworkAdapterInfo { Name = "VPN", IsUp = true, Kind = AdapterKind.Vpn, IPv4Addresses = new[] { "10.8.0.2" }, PrefixLength = 24 }
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "LAN-006");
    }

    [Fact]
    public void Scenario23_DnsFailDoesNotImplyHostDown_WhenIpTcpWorks()
    {
        var snap = BaseClient("printserver");
        snap.Probes = new[]
        {
            new ConnectivityProbeResult { Target = "printserver", Protocol = ProbeProtocol.Tcp, Outcome = ProbeOutcome.Fail, Detail = "NXDOMAIN" },
            OkTcp("192.168.1.10", 445)
        };
        var f = _engine.Evaluate(snap);
        Assert.DoesNotContain(f, x => x.Id == "LAN-001");
    }

    [Fact]
    public async Task Scenario24_RepairPreviewMentionsRebootWhenNeeded_IsNotDefault()
    {
        var elev = new FakeElevationService { IsAdmin = true };
        var profiles = new FakeNetworkProfileService
        {
            Profiles =
            {
                new NetworkConnectionProfile { InterfaceIndex = 12, Name = "Ethernet", NetworkCategory = "Public" }
            }
        };
        var op = new NetworkProfilePrivateRepair(profiles, elev, preferredInterfaceIndex: 12);
        var preview = await op.PreviewChangesAsync();
        Assert.DoesNotContain(preview.Changes, c => c.Contains("netsh int ip reset", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(preview.Changes, c => c == "InterfaceIndex=?");
        Assert.True(preview.Reversible);
    }

    [Fact]
    public void Scenario25_ServerAndManyClientsCommonOutage()
    {
        var server = new DiagnosticSnapshot
        {
            SessionId = "S",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Server,
            Adapters = new[] { LanAdapter("192.168.1.10") },
            Services = new[] { new WindowsServiceInfo { Name = "LanmanServer", Status = "Running" } }
        };
        var clients = Enumerable.Range(1, 4).Select(i =>
        {
            var c = BaseClient("192.168.1.10");
            c.MachineName = "PC" + i;
            c.Probes = new[] { FailIcmp("192.168.1.10"), FailTcp("192.168.1.10", 445) };
            return c;
        }).ToList();

        var cmp = new CompareEngine().Compare(new CompareInput { Server = server, Clients = clients });
        Assert.Contains(cmp.Findings, f => f.Id == "CMP-001");
        Assert.NotEmpty(cmp.InfrastructureHints);
    }

    [Fact]
    public async Task Orchestrator_RejectsUnsafeHost()
    {
        var orch = CreateOrch(new FakeNetworkProbe());
        await Assert.ThrowsAsync<ArgumentException>(() => orch.RunAsync(new DiagnosticRequest
        {
            Role = MachineRole.Client,
            TargetHost = "192.168.1.1 & notepad"
        }));
    }

    [Fact]
    public async Task Orchestrator_IcmpFailTcpPass_EndToEnd()
    {
        var net = new FakeNetworkProbe
        {
            Adapters = { LanAdapter() },
            IcmpResults =
            {
                ["127.0.0.1"] = true,
                ["192.168.1.20"] = true,
                ["192.168.1.1"] = true,
                ["192.168.1.10"] = false
            },
            TcpResults =
            {
                [("192.168.1.10", 445)] = true,
                [("192.168.1.10", 135)] = true,
                [("192.168.1.10", 9100)] = false,
                [("192.168.1.10", 48631)] = false
            }
        };
        var services = new FakeWindowsServiceInspector();
        foreach (var name in new[] { "LanmanServer", "LanmanWorkstation", "FDResPub", "Spooler", "SSDPSRV", "upnphost" })
            services.Services[name] = new WindowsServiceInfo { Name = name, Status = "Running", StartType = "Automatic" };
        var smb = new FakeSmbInspector
        {
            Probe = new SmbProbeResult
            {
                Target = "192.168.1.10",
                Tcp445 = ProbeOutcome.Pass,
                Tcp135 = ProbeOutcome.Pass,
                Unc = ProbeOutcome.Pass
            }
        };
        var orch = new DiagnosticOrchestrator(net, new FakeFirewallInspector(), services, smb, new FakePrinterInspector(), new FakeShaPrintInspector());
        var snap = await orch.RunAsync(new DiagnosticRequest { Role = MachineRole.Client, TargetHost = "192.168.1.10" });
        Assert.Contains(snap.Findings, f => f.Id == "LAN-002");
    }

    [Fact]
    public void Security_NeverSuggestsDisableFirewallOrEnableSmb1()
    {
        var snap = BaseClient("192.168.1.10");
        snap.SmbConfiguration = new SmbConfiguration { EnableSMB1Protocol = true, EnableInsecureGuestLogons = true };
        snap.Probes = new[] { FailIcmp("192.168.1.10"), FailTcp("192.168.1.10", 445) };
        var f = _engine.Evaluate(snap);
        static bool IsUnsafeSuggestion(string a)
        {
            var t = a.Trim();
            return t.StartsWith("Disable the firewall", StringComparison.OrdinalIgnoreCase)
                   || t.StartsWith("Enable SMB1", StringComparison.OrdinalIgnoreCase)
                   || t.StartsWith("Disable SMB signing", StringComparison.OrdinalIgnoreCase)
                   || t.StartsWith("Enable insecure guest", StringComparison.OrdinalIgnoreCase);
        }
        Assert.DoesNotContain(f.SelectMany(x => x.RecommendedActions), IsUnsafeSuggestion);
        Assert.Contains(f, x => x.Id == "SMB-010");
        Assert.Contains(f, x => x.Id == "SMB-011");
    }

    private static DiagnosticOrchestrator CreateOrch(FakeNetworkProbe net)
    {
        var services = new FakeWindowsServiceInspector();
        foreach (var name in new[] { "LanmanServer", "LanmanWorkstation", "FDResPub", "Spooler", "SSDPSRV", "upnphost" })
            services.Services[name] = new WindowsServiceInfo { Name = name, Status = "Running", StartType = "Automatic" };
        return new DiagnosticOrchestrator(net, new FakeFirewallInspector(), services, new FakeSmbInspector(), new FakePrinterInspector(), new FakeShaPrintInspector());
    }

    private static DiagnosticSnapshot BaseClient(string? target) => new()
    {
        SessionId = "T",
        StartedAt = DateTimeOffset.UtcNow,
        Role = MachineRole.Client,
        TargetHost = target,
        Adapters = new[] { LanAdapter() }
    };

    private static ConnectivityProbeResult FailIcmp(string t) => new() { Target = t, Protocol = ProbeProtocol.Icmp, Outcome = ProbeOutcome.Fail, Detail = "timeout" };
    private static ConnectivityProbeResult OkTcp(string t, int p) => new() { Target = t, Protocol = ProbeProtocol.Tcp, Port = p, Outcome = ProbeOutcome.Pass };
    private static ConnectivityProbeResult FailTcp(string t, int p) => new() { Target = t, Protocol = ProbeProtocol.Tcp, Port = p, Outcome = ProbeOutcome.Fail };

    /// <summary>Test-only repair with injectable apply/verify/rollback (production ops no longer accept no-op delegates).</summary>
    private sealed class ScriptableRepair : IRepairOperation
    {
        private readonly Func<CancellationToken, Task> _apply;
        private readonly Func<CancellationToken, Task<bool>> _verify;
        private readonly Func<RepairBackup, CancellationToken, Task<RollbackResult>> _rollback;

        public ScriptableRepair(
            Func<CancellationToken, Task> apply,
            Func<CancellationToken, Task<bool>> verify,
            Func<RepairBackup, CancellationToken, Task<RollbackResult>> rollback)
        {
            _apply = apply;
            _verify = verify;
            _rollback = rollback;
        }

        public string OperationId => "TEST-SCRIPTABLE";
        public string Title => "Scriptable test repair";
        public bool IsImplemented => true;
        public bool SupportsRollback => true;
        public RepairOwnerRole OwnerRole => RepairOwnerRole.LocalAny;
        public RepairTargetMachine TargetMachine => RepairTargetMachine.Local;

        public Task<RepairPrerequisiteResult> CheckPrerequisitesAsync(CancellationToken ct = default)
            => Task.FromResult(new RepairPrerequisiteResult { CanProceed = true, RequiresAdmin = false });

        public Task CollectEvidenceAsync(CancellationToken ct = default) => Task.CompletedTask;

        public Task<RepairPreview> PreviewChangesAsync(CancellationToken ct = default)
            => Task.FromResult(new RepairPreview
            {
                OperationId = OperationId,
                Title = Title,
                Description = "test",
                Reversible = true
            });

        public Task<RepairBackup> BackupAsync(CancellationToken ct = default)
            => Task.FromResult(new RepairBackup
            {
                BackupId = "bak-test",
                Path = "journal",
                CreatedAt = DateTimeOffset.UtcNow,
                PayloadJson = "{}"
            });

        public Task ApplyAsync(CancellationToken ct = default) => _apply(ct);
        public Task<bool> VerifyAsync(CancellationToken ct = default) => _verify(ct);
        public Task<RollbackResult> RollbackAsync(RepairBackup backup, CancellationToken ct = default) => _rollback(backup, ct);
    }
}
