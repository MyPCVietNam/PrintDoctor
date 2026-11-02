using System.IO.Compression;
using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Core.Compare;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Platform.Fakes;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;
using MyPC.LanPrintDoctor.Reports;

namespace MyPC.LanPrintDoctor.UnitTests;

public class Hf2RegressionTests
{
    [Fact]
    public async Task HF2_RemoteAddressFail_EnableNotRun()
    {
        var fw = new FakeFirewallInspector { FailRemoteAddressSet = true };
        var op = new FirewallIcmpEchoRepair(fw, new FakeElevationService { IsAdmin = true });
        await Assert.ThrowsAsync<InvalidOperationException>(() => op.ApplyAsync());
        Assert.Equal(0, fw.IcmpEnableCalls);
    }

    [Fact]
    public async Task HF2_OneGoodOneBadChangedRule_VerifyFails()
    {
        var fw = new FakeFirewallInspector();
        var op = new FilePrintShareRepair(fw, new FakeElevationService { IsAdmin = true });
        await op.CollectEvidenceAsync();
        await op.ApplyAsync();
        // Corrupt one changed rule to Public/Any after apply
        var bad = fw.Rules.First(r => r.RuleId == "FPS-SMB-In-TCP" && r.Profiles == "Private");
        fw.Rules.Remove(bad);
        fw.Rules.Add(new FirewallRuleInfo
        {
            RuleId = bad.RuleId!,
            Name = bad.Name,
            Enabled = true,
            Direction = "Inbound",
            Action = "Allow",
            Protocol = "TCP",
            LocalPorts = "445",
            Profiles = "Private",
            RemoteAddresses = "", // empty ≠ LocalSubnet
            Grouping = bad.Grouping,
            PolicyStore = "ActiveStore"
        });
        Assert.False(await op.VerifyAsync());
    }

    [Fact]
    public async Task HF2_RollbackWrongRemoteAddress_FailsVerified()
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
            },
            FailRemoteAddressRestore = true
        };
        var op = new FirewallIcmpEchoRepair(fw, new FakeElevationService { IsAdmin = true });
        await op.CollectEvidenceAsync();
        var bak = await op.BackupAsync();
        await op.ApplyAsync();
        var rb = await op.RollbackAsync(bak);
        Assert.True(rb.Partial || !rb.Verified);
        Assert.False(rb.Verified);
        Assert.Contains("PARTIAL", rb.Message ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HF2_CrashAfterApplied_BeforeVerify_Uncertain()
    {
        var j = new RepairJournal(Temp("applied"));
        var tx = "tx-applied-no-verify";
        j.Record(tx, "FW-ICMP-ECHO", "ApplyStarted", true);
        j.Record(tx, "FW-ICMP-ECHO", "Applied", true);
        Assert.Equal(RepairRecoveryState.UncertainState, j.GetRecoveryState());
        Assert.Equal(RepairRecoveryState.UncertainState, j.GetRecoveryState(tx));
    }

    [Fact]
    public void HF2_RecoveryFromPriorSession_AfterRestart()
    {
        var root = Temp("journals-root");
        var oldSession = Path.Combine(root, "old-session");
        var j1 = new RepairJournal(oldSession);
        j1.Record("tx-old", "FW-ICMP-ECHO", "ApplyStarted", true);
        j1.Record("tx-old", "FW-ICMP-ECHO", "Applied", true);
        // New process / new journal handle
        Assert.Equal(RepairRecoveryState.UncertainState, RepairJournal.ScanAllSessions(root));
        var listed = RepairJournal.ListUncertain(root);
        Assert.Contains(listed, x => x.TransactionId == "tx-old");
    }

    [Fact]
    public async Task HF2_MultiNic_WrongOrMissingAdapter_Blocked()
    {
        var profiles = new FakeNetworkProfileService
        {
            Profiles =
            {
                new NetworkConnectionProfile { InterfaceIndex = 10, Name = "Ethernet", NetworkCategory = "Public" },
                new NetworkConnectionProfile { InterfaceIndex = 20, Name = "VPN", NetworkCategory = "Public" }
            }
        };
        var elev = new FakeElevationService { IsAdmin = true };
        var noSelect = new NetworkProfilePrivateRepair(profiles, elev, preferredInterfaceIndex: null);
        var preview = await noSelect.PreviewChangesAsync();
        Assert.Contains(preview.Changes, c => c.Contains("InterfaceIndex=?", StringComparison.Ordinal));
        Assert.False((await noSelect.CheckPrerequisitesAsync()).CanProceed);

        var wrong = new NetworkProfilePrivateRepair(profiles, elev, preferredInterfaceIndex: 999);
        Assert.False((await wrong.CheckPrerequisitesAsync()).CanProceed);
    }

    [Fact]
    public async Task HF2_Redaction_NotReversibleFromCommonIpList()
    {
        var snap = new DiagnosticSnapshot
        {
            SessionId = "priv",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Client,
            SchemaVersion = "1.1.0",
            MachineName = "PC1",
            TargetHost = "192.168.1.10",
            Adapters = new[]
            {
                new NetworkAdapterInfo
                {
                    Name = "Ethernet",
                    IsUp = true,
                    MacAddress = "AA:BB:CC:DD:EE:FF",
                    IPv4Addresses = new[] { "192.168.1.20" },
                    DefaultGateway = "192.168.1.1"
                }
            }
        };
        var zip = await new ReportExporter { DefaultRoot = Temp("priv") }.ExportZipAsync(snap, redact: true);
        using var arch = ZipFile.OpenRead(zip);
        using var s = arch.GetEntry("Diagnostics.json")!.Open();
        using var r = new StreamReader(s);
        var body = r.ReadToEnd();
        Assert.DoesNotContain("192.168.1.10", body);
        // Plain SHA256(IP) must not appear (rainbow-tableable); tokens are HMAC with ephemeral key
        var plain = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes("192.168.1.10"))).ToLowerInvariant();
        Assert.DoesNotContain(plain[..16], body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("tok:", body);
    }

    [Fact]
    public void HF2_ClientReport_WrongRole_Rejected()
    {
        var dir = Temp("role");
        var server = Path.Combine(dir, "s.json");
        var client = Path.Combine(dir, "c.json");
        File.WriteAllText(server, """{"schemaVersion":"1.1.0","sessionId":"S","startedAt":"2026-01-01T00:00:00Z","role":"Server","adapters":[{"name":"e","isUp":true,"iPv4Addresses":["192.168.1.10"]}]}""");
        // Wrong: client file labeled Server
        File.WriteAllText(client, """{"schemaVersion":"1.1.0","sessionId":"C","startedAt":"2026-01-01T00:00:00Z","role":"Server","adapters":[{"name":"e","isUp":true,"iPv4Addresses":["192.168.1.20"]}],"probes":[]}""");
        Assert.ThrowsAny<Exception>(() => new ReportCompareService().CompareFiles(server, new[] { client }));
    }

    [Fact]
    public void HF2_PrintBridge_NotCountedAsShaPrintListener()
    {
        // Unit: foreign/empty listening after PID filter ⇒ SHA-003 when process "running" but no owned endpoints
        var engine = new Core.Engine.DecisionEngine();
        var snap = new DiagnosticSnapshot
        {
            SessionId = "sha",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Client,
            SchemaVersion = "1.1.0",
            ShaPrint = new Abstractions.ShaPrint.ShaPrintInstallInfo
            {
                Installed = true,
                ProcessRunning = true,
                ListeningEndpoints = Array.Empty<string>(), // PrintBridge-only ports filtered out
                ListeningCollectionStatus = ProbeOutcome.Pass
            }
        };
        Assert.Contains(engine.Evaluate(snap), f => f.Id == "SHA-003");
    }

    [Fact]
    public void HF2_EmptyRemoteAddress_NotLocalSubnet()
    {
        Assert.False(FirewallRuleScope.IsLocalSubnetScoped(new FirewallRuleInfo
        {
            Name = "x",
            Enabled = true,
            Direction = "Inbound",
            Action = "Allow",
            Profiles = "Private",
            RemoteAddresses = ""
        }));
    }

    private static string Temp(string tag)
    {
        var d = Path.Combine(Path.GetTempPath(), "lpd-hf2-" + tag + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }
}
