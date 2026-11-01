using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Platform.Windows;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;
using System.Text.Json;

namespace MyPC.LanPrintDoctor.UnitTests;

public class P2RegressionTests
{
    [Fact]
    public void P2_00A_SetNetFirewallAddressFilter_AssociatedNetFirewallRule_IsInvalid()
    {
        Assert.DoesNotContain("AssociatedNetFirewallRule", NetSecurityCommandCatalog.SetNetFirewallAddressFilterParameters);
        Assert.Contains("AssociatedNetFirewallRule", NetSecurityCommandCatalog.GetNetFirewallAddressFilterParameters);
        Assert.Contains("RemoteAddress", NetSecurityCommandCatalog.SetNetFirewallRuleParameters);

        const string bad = "Set-NetFirewallAddressFilter -AssociatedNetFirewallRule (Get-NetFirewallRule -Name x) -RemoteAddress LocalSubnet";
        Assert.True(NetSecurityCommandCatalog.IsInvalidSetAddressFilterUsage(bad));

        const string good = "Set-NetFirewallRule -Name x -RemoteAddress LocalSubnet -ErrorAction Stop";
        Assert.True(NetSecurityCommandCatalog.UsesPreferredRemoteAddressMutation(good));
        Assert.False(NetSecurityCommandCatalog.IsInvalidSetAddressFilterUsage(good));
    }

    [Fact]
    public void P2_00A_ProductionScripts_DoNotUseInvalidSetAssociated()
    {
        var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src"));
        var files = Directory.Exists(root)
            ? Directory.GetFiles(root, "*WindowsInspectors*.cs", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(root, "*OwnedFirewall*.cs", SearchOption.AllDirectories))
                .ToArray()
            : Array.Empty<string>();
        Assert.NotEmpty(files);
        foreach (var f in files)
        {
            var text = File.ReadAllText(f);
            Assert.False(NetSecurityCommandCatalog.IsInvalidSetAddressFilterUsage(text),
                $"Invalid Set-NetFirewallAddressFilter -AssociatedNetFirewallRule in {f}");
        }
    }

    [Fact]
    public void P2_00B_EnabledFalse_String_NotTruthy()
    {
        using var doc = JsonDocument.Parse("\"False\"");
        Assert.False(PowerShellJson.IsTruthy(doc.RootElement));
        Assert.True(PowerShellJson.TryParseEnabled(doc.RootElement, out var en));
        Assert.False(en);

        using var t = JsonDocument.Parse("\"True\"");
        Assert.True(PowerShellJson.IsTruthy(t.RootElement));

        using var junk = JsonDocument.Parse("\"GpoMaybe\"");
        Assert.False(PowerShellJson.TryParseEnabled(junk.RootElement, out _));
    }

    [Fact]
    public void P2_00C_MutationIntent_WithoutApply_IsUncertain()
    {
        var j = new RepairJournal(Path.Combine(Path.GetTempPath(), "lpd-p2-" + Guid.NewGuid().ToString("N")));
        j.RecordMutationIntent("tx1", "FW-OWNED-ICMP4", "[\"MyPC.PrintDoctor.ICMPv4.Private\"]", "[]");
        Assert.Equal(RepairRecoveryState.UncertainState, j.GetRecoveryState());
    }

    [Fact]
    public void P2_00C_CorruptJournal_FailClosed()
    {
        var dir = Path.Combine(Path.GetTempPath(), "lpd-p2-corrupt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "repair-journal.json"), "{not-json");
        var j = new RepairJournal(dir);
        Assert.True(j.IsCorrupt);
        Assert.Equal(RepairRecoveryState.CorruptJournal, j.GetRecoveryState());
        Assert.Throws<InvalidOperationException>(() => j.Record("tx", "op", "Backup", true));
    }

    [Fact]
    public void P2_01_RootCause_CaseB_IcmpFail_TcpPass()
    {
        var snap = new DiagnosticSnapshot
        {
            SessionId = "rc",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Client,
            TargetHost = "192.168.1.10",
            Adapters = new[] { new NetworkAdapterInfo { Name = "Ethernet", IsUp = true, IPv4Addresses = new[] { "192.168.1.20" } } },
            Probes = new[]
            {
                new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Icmp, Outcome = ProbeOutcome.Fail },
                new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Tcp, Port = 445, Outcome = ProbeOutcome.Pass }
            }
        };
        var findings = new NetworkRootCauseEngine().Analyze(snap);
        Assert.Contains(findings, f => f.CaseId == "RC-CASE-B");
        Assert.DoesNotContain(findings, f => f.CaseId == "RC-CASE-A" && f.InfrastructureActionRequired);
    }

    [Fact]
    public void P2_01_RootCause_CaseA_InfrastructureHint()
    {
        var snap = new DiagnosticSnapshot
        {
            SessionId = "rca",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Client,
            TargetHost = "192.168.1.10",
            Adapters = new[] { new NetworkAdapterInfo { Name = "Ethernet", IsUp = true } },
            Probes = new[]
            {
                new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Icmp, Outcome = ProbeOutcome.Fail },
                new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Tcp, Port = 445, Outcome = ProbeOutcome.Fail },
                new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Tcp, Port = 48631, Outcome = ProbeOutcome.Fail }
            }
        };
        var findings = new NetworkRootCauseEngine().Analyze(snap);
        Assert.Contains(findings, f => f.CaseId == "RC-CASE-A" && f.InfrastructureActionRequired);
    }

    [Fact]
    public void P2_02_Server_PrefersOwnedIcmpRepair()
    {
        var snap = new DiagnosticSnapshot
        {
            SessionId = "srv",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Server,
            TargetHost = "192.168.1.10",
            Adapters = new[] { new NetworkAdapterInfo { Name = "Ethernet", IsUp = true, IPv4Addresses = new[] { "192.168.1.10" }, Category = NetworkCategory.Private } },
            Probes = new[]
            {
                new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Icmp, Outcome = ProbeOutcome.Fail },
                new ConnectivityProbeResult { Target = "192.168.1.10", Protocol = ProbeProtocol.Tcp, Port = 445, Outcome = ProbeOutcome.Pass }
            }
        };
        var f = new DecisionEngine().Evaluate(snap).First(x => x.Id == "LAN-002");
        Assert.Equal("FW-OWNED-ICMP4", f.RepairId);
        Assert.Equal(RepairOwnerRole.LocalServer, f.RepairOwner);
    }

    [Fact]
    public void P2_02_OwnedSpec_NeverAnyRemote_NeverOpens48632()
    {
        foreach (var spec in new[]
                 {
                     OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet(),
                     OwnedFirewallSpec.Smb445PrivateLocalSubnet(),
                     OwnedFirewallSpec.ShaPrint48631(),
                     OwnedFirewallSpec.ShaPrint48633Udp()
                 })
        {
            Assert.StartsWith("MyPC.PrintDoctor.", spec.RuleName);
            Assert.Equal("Private", spec.Profile);
            Assert.False(spec.RemoteAddress.Equals("Any", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain("48632", spec.RuleName);
            Assert.NotEqual("48632", spec.LocalPortOrIcmp);
        }
    }

    [Fact]
    public async Task P2_02_OwnedFirewall_CreateDisabledThenEnable_ScriptOrder()
    {
        string? captured = null;
        var runner = new RecordingRunner((_, script) =>
        {
            captured = script;
            return new ProcessResult { ExitCode = 0, StdOut = "CHANGED:MyPC.PrintDoctor.ICMPv4.Private" };
        });
        var elev = new StubElevation { Admin = true };
        var op = new OwnedFirewallRuleRepair(runner, elev, OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var prereq = await op.CheckPrerequisitesAsync();
        Assert.True(prereq.CanProceed);
        await op.ApplyAsync();
        Assert.NotNull(captured);
        Assert.Contains("-Enabled False", captured, StringComparison.OrdinalIgnoreCase);
        var createIdx = captured!.IndexOf("New-NetFirewallRule", StringComparison.OrdinalIgnoreCase);
        var enableIdx = captured.IndexOf("Enable-NetFirewallRule", StringComparison.OrdinalIgnoreCase);
        Assert.True(createIdx >= 0 && enableIdx > createIdx);
        Assert.Contains("CREATED_ENABLED_TOO_EARLY", captured, StringComparison.Ordinal);
        Assert.DoesNotContain("48632", captured, StringComparison.Ordinal);
    }

    [Fact]
    public async Task P2_02_OwnedFirewall_RefuseDeleteNonOwned()
    {
        var runner = new RecordingRunner((_, script) =>
        {
            Assert.Contains("REFUSE_DELETE_NON_OWNED", script, StringComparison.Ordinal);
            return new ProcessResult { ExitCode = 0, StdOut = "OK:REMOVED" };
        });
        var op = new OwnedFirewallRuleRepair(runner, new StubElevation { Admin = true }, OwnedFirewallSpec.Smb445PrivateLocalSubnet());
        var rb = await op.RollbackAsync(new RepairBackup
        {
            BackupId = "b",
            Path = "journal",
            CreatedAt = DateTimeOffset.UtcNow,
            PayloadJson = "null"
        });
        Assert.True(rb.Succeeded);
    }

    private sealed class StubElevation : IElevationService
    {
        public bool Admin { get; init; }
        public bool IsAdministrator() => Admin;
        public Task<bool> EnsureElevatedAsync(CancellationToken ct = default) => Task.FromResult(Admin);
    }

    private sealed class RecordingRunner : IProcessRunner
    {
        private readonly Func<string, string, ProcessResult> _handler;
        public RecordingRunner(Func<string, string, ProcessResult> handler) => _handler = handler;
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> args, TimeSpan? timeout = null, CancellationToken ct = default)
        {
            var script = args.Count > 0 ? args[^1] : "";
            return Task.FromResult(_handler(fileName, script));
        }
    }
}
