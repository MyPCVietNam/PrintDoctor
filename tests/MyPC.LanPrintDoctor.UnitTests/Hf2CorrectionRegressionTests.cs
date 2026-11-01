using System.Text.Json;
using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Network;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Smb;
using MyPC.LanPrintDoctor.Core.Engine;
using MyPC.LanPrintDoctor.Core.Models;
using MyPC.LanPrintDoctor.Platform.Fakes;
using MyPC.LanPrintDoctor.Platform.Windows;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;

namespace MyPC.LanPrintDoctor.UnitTests;

public class Hf2CorrectionRegressionTests
{
    [Fact]
    public void HF2C_VerifyFalse_RollbackVerifiedFalse_Uncertain()
    {
        var root = Temp("vf-root");
        var j = new RepairJournal(Path.Combine(root, "session"));
        var tx = "tx-vf";
        j.Record(tx, "FW-ICMP-ECHO", "ApplyStarted", true);
        j.Record(tx, "FW-ICMP-ECHO", "Applied", true);
        j.Record(tx, "FW-ICMP-ECHO", "Verify", false);
        j.Record(tx, "FW-ICMP-ECHO", "RollbackStarted", true);
        j.Record(tx, "FW-ICMP-ECHO", "RollbackVerified", false, "PARTIAL_ROLLBACK");
        Assert.Equal(RepairRecoveryState.UncertainState, j.GetRecoveryState());
        Assert.Equal(RepairRecoveryState.UncertainState, RepairJournal.ScanAllSessions(root));
    }

    [Fact]
    public void HF2C_Applied_RollbackFailed_Uncertain()
    {
        var j = new RepairJournal(Temp("rb-fail"));
        var tx = "tx-rb";
        j.Record(tx, "FW-FILE-PRINT-SHARE", "ApplyStarted", true);
        j.Record(tx, "FW-FILE-PRINT-SHARE", "Applied", true);
        j.Record(tx, "FW-FILE-PRINT-SHARE", "Verify", false);
        j.Record(tx, "FW-FILE-PRINT-SHARE", "RollbackStarted", true);
        j.Record(tx, "FW-FILE-PRINT-SHARE", "Rollback", false, "restore failed");
        j.Record(tx, "FW-FILE-PRINT-SHARE", "RollbackVerified", false);
        Assert.Equal(RepairRecoveryState.UncertainState, j.GetRecoveryState(tx));
    }

    [Fact]
    public void HF2C_CorruptJournal_BlockedNotClean()
    {
        var root = Temp("corrupt-root");
        var dir = Path.Combine(root, "session");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "repair-journal.json"), "{not-valid-json[[[");
        var j = new RepairJournal(dir);
        Assert.True(j.IsCorrupt);
        Assert.Equal(RepairRecoveryState.CorruptJournal, j.GetRecoveryState());
        Assert.Equal(RepairRecoveryState.CorruptJournal, RepairJournal.ScanAllSessions(root));
    }

    [Fact]
    public async Task HF2C_Executor_PriorUncertain_BlocksApply()
    {
        var dir = Temp("exec-block");
        var j = new RepairJournal(dir);
        j.Record("prior", "FW-ICMP-ECHO", "ApplyStarted", true);
        j.Record("prior", "FW-ICMP-ECHO", "Applied", true);
        // Verify missing → UNCERTAIN
        Assert.Equal(RepairRecoveryState.UncertainState, j.GetRecoveryState());

        var fw = new FakeFirewallInspector();
        var op = new FirewallIcmpEchoRepair(fw, new FakeElevationService { IsAdmin = true });
        var result = await new RepairExecutor(j).ExecuteAsync(op, userConfirmed: true);
        Assert.Equal(DiagnosticStatus.Blocked, result.Status);
        Assert.False(result.Applied);
        Assert.Contains("UNCERTAIN_STATE", result.Message ?? "", StringComparison.Ordinal);
        Assert.Equal(0, fw.IcmpEnableCalls);
    }

    [Fact]
    public async Task HF2C_Executor_CorruptJournal_BlocksApply()
    {
        var dir = Temp("exec-corrupt");
        File.WriteAllText(Path.Combine(dir, "repair-journal.json"), "CORRUPT<<<");
        var j = new RepairJournal(dir);
        var fw = new FakeFirewallInspector();
        var result = await new RepairExecutor(j).ExecuteAsync(
            new FirewallIcmpEchoRepair(fw, new FakeElevationService { IsAdmin = true }), userConfirmed: true);
        Assert.Equal(DiagnosticStatus.Blocked, result.Status);
        Assert.Contains("CORRUPT_JOURNAL", result.Message ?? "", StringComparison.Ordinal);
        Assert.Equal(0, fw.IcmpEnableCalls);
    }

    [Fact]
    public async Task HF2C_Rollback_OnlyTouchesTransactionChangedRules()
    {
        var publicUntouched = new FirewallRuleInfo
        {
            RuleId = "FPS-SMB-In-TCP",
            Name = "FPS-SMB-In-TCP",
            Enabled = false,
            Direction = "Inbound",
            Action = "Allow",
            Protocol = "TCP",
            LocalPorts = "445",
            Profiles = "Public",
            RemoteAddresses = "Any",
            PolicyStore = "ActiveStore"
        };
        var privateSmb = new FirewallRuleInfo
        {
            RuleId = "FPS-SMB-In-TCP",
            Name = "FPS-SMB-In-TCP",
            Enabled = false,
            Direction = "Inbound",
            Action = "Allow",
            Protocol = "TCP",
            LocalPorts = "445",
            Profiles = "Private",
            RemoteAddresses = "Any",
            PolicyStore = "ActiveStore"
        };
        var spooler = new FirewallRuleInfo
        {
            RuleId = "FPS-SpoolSvc-In-TCP",
            Name = "FPS-SpoolSvc-In-TCP",
            Enabled = false,
            Direction = "Inbound",
            Action = "Allow",
            Protocol = "TCP",
            LocalPorts = "RPC",
            Profiles = "Private",
            RemoteAddresses = "Any",
            PolicyStore = "ActiveStore"
        };

        var fw = new FakeFirewallInspector
        {
            FailMidApplyAfterFirst = true,
            Rules = { publicUntouched, privateSmb, spooler }
        };
        var op = new FilePrintShareRepair(fw, new FakeElevationService { IsAdmin = true });
        await op.CollectEvidenceAsync();
        var bak = await op.BackupAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => op.ApplyAsync());
        Assert.Equal(new[] { "FPS-SMB-In-TCP" }, op.LastChangedRuleIds);

        var publicBefore = JsonSerializer.Serialize(fw.Rules.First(r => r.Profiles == "Public"));
        var rb = await op.RollbackAsync(bak);
        Assert.Contains("FPS-SMB-In-TCP", fw.LastRestoredRuleIds);
        Assert.DoesNotContain("FPS-SpoolSvc-In-TCP", fw.LastRestoredRuleIds);
        var publicAfter = JsonSerializer.Serialize(fw.Rules.First(r => r.Profiles == "Public"));
        Assert.Equal(publicBefore, publicAfter);
        // Spooler was never in ChangedRuleIds — must remain as originally in Rules list (not restored from full backup)
        Assert.DoesNotContain(fw.LastRestoredRuleIds, id => id.Contains("Spool", StringComparison.OrdinalIgnoreCase));
        _ = rb;
    }

    [Fact]
    public void HF2C_PowerShellCollectorFail_UnknownNotPass()
    {
        var engine = new DecisionEngine();
        var snap = new DiagnosticSnapshot
        {
            SessionId = "ps-fail",
            StartedAt = DateTimeOffset.UtcNow,
            Role = MachineRole.Server,
            SchemaVersion = "1.1.0",
            SharingToggles = new SharingToggleState
            {
                NetworkDiscovery = ProbeOutcome.Unknown,
                FileAndPrinterSharing = ProbeOutcome.Unknown,
                Detail = "PowerShell failed"
            },
            SmbConfiguration = new SmbConfiguration
            {
                CollectionStatus = ProbeOutcome.Unknown,
                Notes = "Unable to read SMB"
            }
        };
        var findings = engine.Evaluate(snap);
        Assert.DoesNotContain(findings, f =>
            f.Status == DiagnosticStatus.Pass
            && (f.Id.StartsWith("SMB", StringComparison.Ordinal) || f.Title.Contains("Sharing", StringComparison.OrdinalIgnoreCase)));
        Assert.Contains(findings, f => f.Status is DiagnosticStatus.Unknown or DiagnosticStatus.Warning or DiagnosticStatus.Fail);
    }

    [Fact]
    public async Task HF2C_PsFixture_PartialChanged_ParsedOnFailure()
    {
        var runner = new RecordingRunner((file, script) =>
        {
            if (script.Contains("FPS-SMB-In-TCP", StringComparison.Ordinal))
                return new ProcessResult { ExitCode = 1, StdOut = "PARTIAL_CHANGED:FPS-SMB-In-TCP|ERR:boom" };
            return new ProcessResult { ExitCode = 1, StdOut = "", StdErr = "fail" };
        });
        var fw = new PowerShellFirewallInspector(runner);
        var result = await fw.EnableFileAndPrinterSharingAsync();
        Assert.False(result.Success);
        Assert.Equal(new[] { "FPS-SMB-In-TCP" }, result.ChangedRuleIds.ToArray());
    }

    private sealed class RecordingRunner : IProcessRunner
    {
        private readonly Func<string, string, ProcessResult> _handler;
        public RecordingRunner(Func<string, string, ProcessResult> handler) => _handler = handler;
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan? timeout = null, CancellationToken ct = default)
            => Task.FromResult(_handler(fileName, arguments.LastOrDefault() ?? ""));
    }

    private static string Temp(string tag)
    {
        var d = Path.Combine(Path.GetTempPath(), "lpd-hf2c-" + tag + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }
}
