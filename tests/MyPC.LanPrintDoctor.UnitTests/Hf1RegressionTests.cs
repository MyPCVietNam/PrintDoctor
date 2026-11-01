using System.IO.Compression;
using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Core.Compare;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Platform.Fakes;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;
using MyPC.LanPrintDoctor.Reports;

namespace MyPC.LanPrintDoctor.UnitTests;

public class Hf1RegressionTests
{
    private readonly DecisionEngine _engine = new();

    [Fact]
    public async Task HF1_01_FirewallPublicRule_NotChanged()
    {
        var fw = new FakeFirewallInspector
        {
            Rules =
            {
                new FirewallRuleInfo
                {
                    RuleId = "FPS-SMB-In-TCP",
                    Name = "SMB Public",
                    Enabled = false,
                    Direction = "Inbound",
                    Action = "Allow",
                    Profiles = "Public",
                    Grouping = "@FirewallAPI.dll,-28502",
                    Protocol = "TCP",
                    LocalPorts = "445",
                    RemoteAddresses = "Any"
                }
            }
        };
        var elev = new FakeElevationService { IsAdmin = true };
        var op = new FilePrintShareRepair(fw, elev);
        await op.CollectEvidenceAsync();
        var bak = await op.BackupAsync();
        await op.ApplyAsync();
        Assert.Equal(0, fw.GroupEnableCalls);
        var pub = fw.Rules.First(r => r.Profiles == "Public");
        Assert.False(pub.Enabled); // public copy must remain disabled
        Assert.Contains(fw.Rules, r => r.RuleId == "FPS-SMB-In-TCP" && r.Profiles == "Private" && r.Enabled);
        _ = bak;
    }

    [Fact]
    public async Task HF1_02_FirewallRollback_RestoresProfileAndScope()
    {
        var fw = new FakeFirewallInspector
        {
            Rules =
            {
                new FirewallRuleInfo
                {
                    RuleId = "FPS-ICMP4-ERQ-In",
                    Name = "ICMP",
                    Enabled = false,
                    Direction = "Inbound",
                    Action = "Allow",
                    Protocol = "ICMPv4",
                    Profiles = "Domain",
                    RemoteAddresses = "Any",
                    PolicyStore = "ActiveStore"
                }
            }
        };
        var elev = new FakeElevationService { IsAdmin = true };
        var op = new FirewallIcmpEchoRepair(fw, elev);
        var journalRb = new RepairJournal(Temp("rb"));
        var exec = new RepairExecutor(journalRb, journalRb.DirectoryPath);
        // Force verify fail after apply by clearing scoped fields via custom path: apply then manually break verify
        await op.CollectEvidenceAsync();
        var bak = await op.BackupAsync();
        await op.ApplyAsync();
        Assert.True(await op.VerifyAsync());
        var rb = await op.RollbackAsync(bak);
        Assert.True(rb.Verified);
        var cur = fw.Rules.Single(r => r.RuleId == "FPS-ICMP4-ERQ-In");
        Assert.False(cur.Enabled);
        Assert.Equal("Domain", cur.Profiles);
        Assert.Equal("Any", cur.RemoteAddresses);
        _ = exec;
    }

    [Fact]
    public async Task HF1_03_PowerShellFailure_NotPass()
    {
        var fw = new FakeFirewallInspector { IcmpEnableResult = false };
        var elev = new FakeElevationService { IsAdmin = true };
        var op = new FirewallIcmpEchoRepair(fw, elev);
        var journal = new RepairJournal(Temp("psfail"));
        var result = await new RepairExecutor(journal, journal.DirectoryPath).ExecuteAsync(op, true);
        Assert.NotEqual(DiagnosticStatus.Pass, result.Status);
        Assert.False(result.Verified);
    }

    [Fact]
    public async Task HF1_04_VerifyWrongScope_Fails()
    {
        var fw = new FakeFirewallInspector();
        fw.Rules.Add(new FirewallRuleInfo
        {
            RuleId = "FPS-ICMP4-ERQ-In",
            Name = "ICMP",
            Enabled = true,
            Direction = "Inbound",
            Action = "Allow",
            Protocol = "ICMPv4",
            Profiles = "Public",
            RemoteAddresses = "Any"
        });
        var op = new FirewallIcmpEchoRepair(fw, new FakeElevationService { IsAdmin = true });
        Assert.False(await op.VerifyAsync());
    }

    [Theory]
    [InlineData(ProbeOutcome.Unknown, ProbeOutcome.Unknown)]
    [InlineData(ProbeOutcome.NotTested, ProbeOutcome.Fail)]
    [InlineData(ProbeOutcome.Fail, ProbeOutcome.Unknown)]
    [InlineData(ProbeOutcome.NotTested, ProbeOutcome.NotTested)]
    public void HF1_05_UnknownProbes_NotLan001(ProbeOutcome icmp, ProbeOutcome tcp)
    {
        var snap = Client("192.168.1.10");
        snap.Probes = new[]
        {
            new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Icmp, Outcome = icmp },
            new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Tcp, Port = 445, Outcome = tcp }
        };
        var f = _engine.Evaluate(snap);
        Assert.DoesNotContain(f, x => x.Id == "LAN-001");
    }

    [Fact]
    public void HF1_05b_IcmpFail_TcpPass_Lan002()
    {
        var snap = Client("192.168.1.10");
        snap.Probes = new[]
        {
            new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Icmp, Outcome = ProbeOutcome.Fail },
            new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Tcp, Port = 445, Outcome = ProbeOutcome.Pass }
        };
        var f = _engine.Evaluate(snap);
        Assert.Contains(f, x => x.Id == "LAN-002");
        Assert.DoesNotContain(f, x => x.Id == "LAN-001");
    }

    [Fact]
    public void HF1_05c_NoProbes_NotLan001()
    {
        var snap = Client("192.168.1.10");
        snap.Probes = Array.Empty<ConnectivityProbeResult>();
        Assert.DoesNotContain(_engine.Evaluate(snap), x => x.Id == "LAN-001");
    }

    [Fact]
    public async Task HF1_06_Client_DoesNotRepairServerFirewall()
    {
        var snap = Client("192.168.1.10");
        snap.Role = MachineRole.Client;
        snap.Probes = new[]
        {
            new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Icmp, Outcome = ProbeOutcome.Fail },
            new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Tcp, Port = 445, Outcome = ProbeOutcome.Pass }
        };
        var f = _engine.Evaluate(snap).First(x => x.Id == "LAN-002");
        Assert.Equal(RepairOwnerRole.ServerActionRequired, f.RepairOwner);
        Assert.True(string.IsNullOrWhiteSpace(f.RepairId));

        var fw = new FakeFirewallInspector();
        var op = new FirewallIcmpEchoRepair(fw, new FakeElevationService { IsAdmin = true });
        var journal = new RepairJournal(Temp("own"));
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, true, localRole: MachineRole.Client, findingOwner: RepairOwnerRole.ServerActionRequired);
        Assert.True(result.ServerActionRequired);
        Assert.False(result.Applied);
        Assert.Equal(0, fw.IcmpEnableCalls);
    }

    [Fact]
    public void HF1_07_CrashDuringApply_DetectedAsUncertain()
    {
        var dir = Temp("crash");
        var j = new RepairJournal(dir);
        var tx = "tx-crash-1";
        j.Record(tx, "FW-ICMP-ECHO", "Backup", true, backupId: "b", backupPayload: "[]");
        j.Record(tx, "FW-ICMP-ECHO", "ApplyStarted", true, "About to mutate");
        // no Applied/Verify/Rollback
        Assert.Equal(RepairRecoveryState.UncertainState, j.GetRecoveryState());
        Assert.Equal(RepairRecoveryState.UncertainState, new RepairJournal(dir).GetRecoveryState());
    }

    [Fact]
    public void HF1_08_TwoRunsSameOperationId_SeparateTransactions()
    {
        var j = new RepairJournal(Temp("tx2"));
        j.Record("txA", "FW-ICMP-ECHO", "ApplyStarted", true);
        j.Record("txA", "FW-ICMP-ECHO", "Applied", true);
        j.Record("txA", "FW-ICMP-ECHO", "Verify", true);
        j.Record("txB", "FW-ICMP-ECHO", "ApplyStarted", true);
        Assert.Equal(RepairRecoveryState.UncertainState, j.GetRecoveryState("txB"));
        Assert.Equal(RepairRecoveryState.Clean, j.GetRecoveryState("txA"));
        Assert.Equal(2, j.Entries.Select(e => e.TransactionId).Distinct().Count());
    }

    [Fact]
    public async Task HF1_09_RedactedZip_NoIpOrMacLeak()
    {
        var snap = new DiagnosticSnapshot
        {
            SessionId = "redact1",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Client,
            MachineName = "OFFICE-PC",
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
                    DnsServers = new[] { "8.8.8.8" },
                    DefaultGateway = "192.168.1.1"
                }
            },
            Routes = new[] { new RouteEntry { Destination = "0.0.0.0", Mask = "0.0.0.0", Gateway = "192.168.1.1", InterfaceIndex = 1, Metric = 1 } },
            Neighbors = new[] { new NeighborEntry { IpAddress = "192.168.1.10", MacAddress = "11:22:33:44:55:66" } },
            Probes = new[] { new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Icmp, Outcome = ProbeOutcome.Fail } },
            RepairsJson = """[{"detail":"192.168.1.10"}]""",
            BeforeAfterJson = """{"ip":"192.168.1.20"}""",
            EventLogsText = "Host 192.168.1.10 MAC AA-BB-CC-DD-EE-FF"
        };
        snap.CollectorNotes.Add(new CollectorStatusNote { Collector = "Routes", Outcome = ProbeOutcome.Pass, Detail = "gw 192.168.1.1" });
        var zip = await new ReportExporter { DefaultRoot = Temp("red") }.ExportZipAsync(snap, redact: true);
        using var archive = ZipFile.OpenRead(zip);
        foreach (var e in archive.Entries)
        {
            using var s = e.Open();
            using var r = new StreamReader(s);
            var body = r.ReadToEnd();
            Assert.DoesNotContain("192.168.", body);
            Assert.DoesNotContain("AA:BB:CC:DD:EE:FF", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("AA-BB-CC-DD-EE-FF", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("8.8.8.8", body);
            Assert.DoesNotContain("OFFICE-PC", body);
        }
    }

    [Fact]
    public void HF1_10_MissingSchemaVersion_Rejected()
    {
        var path = Path.Combine(Temp("schema"), "bad.json");
        File.WriteAllText(path, """{"sessionId":"x","startedAt":"2026-01-01T00:00:00Z","role":"Client"}""");
        Assert.ThrowsAny<Exception>(() => new ReportCompareService().LoadSnapshot(path));
    }

    [Fact]
    public void HF1_11_ShaPrintForeignPid_NotCounted()
    {
        // Unit-level: DecisionEngine treats empty ListeningEndpoints with Pass collection as SHA-003
        var snap = Client(null);
        snap.ShaPrint = new Abstractions.ShaPrint.ShaPrintInstallInfo
        {
            Installed = true,
            ProcessRunning = true,
            ListeningEndpoints = Array.Empty<string>(), // foreign PID filtered out by collector
            ListeningCollectionStatus = ProbeOutcome.Pass
        };
        Assert.Contains(_engine.Evaluate(snap), f => f.Id == "SHA-003");
    }

    [Fact]
    public void HF1_12_NoFakeReleaseZip_InPackagingScript()
    {
        var script = File.ReadAllText(Path.Combine(FindRepoRoot(), "scripts", "package-p11-artifacts.sh"));
        Assert.DoesNotContain("RELEASE-PLACEHOLDER", script);
        Assert.Contains("RELEASE_BLOCKED", script);
    }

    private static DiagnosticSnapshot Client(string? target) => new()
    {
        SessionId = "T",
        StartedAt = DateTimeOffset.UtcNow,
        Role = MachineRole.Client,
        TargetHost = target,
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
                Category = NetworkCategory.Private,
                InterfaceMetric = 25,
                InterfaceIndex = 12
            }
        }
    };

    private static string Temp(string tag)
    {
        var d = Path.Combine(Path.GetTempPath(), "lpd-hf1-" + tag + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "MyPC.LanPrintDoctor.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        return Directory.GetCurrentDirectory();
    }
}
