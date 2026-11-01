using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Firewall;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Platform.Fakes;
using MyPC.LanPrintDoctor.Platform.Windows;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;

namespace MyPC.LanPrintDoctor.UnitTests;

public class FinalTwoSafetyDefectTests
{
    [Fact]
    public async Task D1_SetRulePass_AddressFilterFail_TracksIntent_AndRestoresOrUncertain()
    {
        var fw = new FakeFirewallInspector
        {
            FailAddressFilterAfterProfileSet = true,
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
                    PolicyStore = "ActiveStore",
                    IcmpTypesAndCodes = "8"
                }
            }
        };

        var result = await fw.EnableScopedIcmpEchoAsync();
        Assert.False(result.Success);
        Assert.Contains("FPS-ICMP4-ERQ-In", result.ChangedRuleIds);
        Assert.Equal(0, fw.IcmpEnableCalls);
        Assert.True(result.ControlledRollbackSucceeded);
        Assert.False(result.Uncertain);
        var restored = fw.Rules.First(r => r.RuleId == "FPS-ICMP4-ERQ-In");
        Assert.Equal("Domain", restored.Profiles);
        Assert.Equal("Any", restored.RemoteAddresses);

        // Rollback failure path ⇒ UNCERTAIN_STATE (never Clean)
        var fw2 = new FakeFirewallInspector
        {
            FailAddressFilterAfterProfileSet = true,
            FailControlledRollback = true,
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
        var bad = await fw2.EnableScopedIcmpEchoAsync();
        Assert.False(bad.Success);
        Assert.True(bad.Uncertain);
        Assert.Contains("UNCERTAIN_STATE", bad.Detail ?? "", StringComparison.Ordinal);
        Assert.Contains("FPS-ICMP4-ERQ-In", bad.ChangedRuleIds);
    }

    [Fact]
    public async Task D1_PsScript_RecordsTrackedBeforeFirstSet_AndHasControlledRollback()
    {
        string? captured = null;
        var runner = new ScriptCaptureRunner((file, script) =>
        {
            captured = script;
            return new ProcessResult
            {
                ExitCode = 1,
                StdOut = "PARTIAL_CHANGED:FPS-ICMP4-ERQ-In|ROLLBACK_OK|ERR:REMOTE_NOT_SET"
            };
        });
        var fw = new PowerShellFirewallInspector(runner);
        var result = await fw.EnableScopedIcmpEchoAsync();
        Assert.False(result.Success);
        Assert.Equal(new[] { "FPS-ICMP4-ERQ-In" }, result.ChangedRuleIds.ToArray());
        Assert.True(result.ControlledRollbackSucceeded);
        Assert.NotNull(captured);
        var trackIdx = captured!.IndexOf("$tracked.Add", StringComparison.Ordinal);
        Assert.True(trackIdx >= 0, "expected $tracked.Add intent marker");
        // First mutation Set after intent (ignore Set-* inside Restore-RuleSnap helper defined earlier).
        var firstSetAfterTrack = captured.IndexOf("Set-NetFirewallRule", trackIdx, StringComparison.Ordinal);
        Assert.True(firstSetAfterTrack > trackIdx, "mutation intent must be recorded before first Set-NetFirewallRule in apply path");
        Assert.False(NetSecurityCommandCatalog.IsInvalidSetAddressFilterUsage(captured));
        Assert.Contains("Get-RuleSnap", captured, StringComparison.Ordinal);
        Assert.Contains("Restore-RuleSnap", captured, StringComparison.Ordinal);
        Assert.Contains("UNCERTAIN_STATE", captured, StringComparison.Ordinal);
    }

    [Fact]
    public void D2_EmptyJournal_IsCorrupt_NotClean()
    {
        var dir = Temp("empty-j");
        File.WriteAllText(Path.Combine(dir, "repair-journal.json"), "   \n\t  ");
        var j = new RepairJournal(dir);
        Assert.True(j.IsCorrupt);
        Assert.Equal(RepairRecoveryState.CorruptJournal, j.GetRecoveryState());
        Assert.Throws<InvalidOperationException>(() => j.Record("tx", "OP", "Apply", true));
        // Must not overwrite corrupt file
        Assert.True(string.IsNullOrWhiteSpace(File.ReadAllText(Path.Combine(dir, "repair-journal.json")).Trim())
                    || File.ReadAllText(Path.Combine(dir, "repair-journal.json")).Contains('\n'));
        var onDisk = File.ReadAllText(Path.Combine(dir, "repair-journal.json"));
        Assert.DoesNotContain("Apply", onDisk, StringComparison.Ordinal);
    }

    [Fact]
    public void D2_MissingJournal_IsClean_NotCorrupt()
    {
        var dir = Temp("missing-j");
        var j = new RepairJournal(dir);
        Assert.False(j.IsCorrupt);
        Assert.Equal(RepairRecoveryState.Clean, j.GetRecoveryState());
        Assert.False(File.Exists(Path.Combine(dir, "repair-journal.json")));
    }

    [Fact]
    public void D2_EmptyJournal_CrossSession_ScanDetectsCorrupt()
    {
        var root = Temp("empty-root");
        var session = Path.Combine(root, "old-session");
        Directory.CreateDirectory(session);
        File.WriteAllText(Path.Combine(session, "repair-journal.json"), "");
        Assert.Equal(RepairRecoveryState.CorruptJournal, RepairJournal.ScanAllSessions(root));
        Assert.Contains(RepairJournal.ListUncertain(root), x => x.Detail.Contains("CORRUPT", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task D2_EmptyJournal_Executor_Blocked()
    {
        var dir = Temp("empty-exec");
        File.WriteAllText(Path.Combine(dir, "repair-journal.json"), "\r\n");
        var j = new RepairJournal(dir);
        var fw = new FakeFirewallInspector();
        var result = await new RepairExecutor(j).ExecuteAsync(
            new FirewallIcmpEchoRepair(fw, new FakeElevationService { IsAdmin = true }), userConfirmed: true);
        Assert.Equal(DiagnosticStatus.Blocked, result.Status);
        Assert.Contains("CORRUPT_JOURNAL", result.Message ?? "", StringComparison.Ordinal);
        Assert.Equal(0, fw.IcmpEnableCalls);
        Assert.DoesNotContain("ApplyStarted", File.ReadAllText(Path.Combine(dir, "repair-journal.json")), StringComparison.Ordinal);
    }

    private sealed class ScriptCaptureRunner : IProcessRunner
    {
        private readonly Func<string, string, ProcessResult> _h;
        public ScriptCaptureRunner(Func<string, string, ProcessResult> h) => _h = h;
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan? timeout = null, CancellationToken ct = default)
            => Task.FromResult(_h(fileName, arguments.LastOrDefault() ?? ""));
    }

    private static string Temp(string tag)
    {
        var d = Path.Combine(Path.GetTempPath(), "lpd-final2-" + tag + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }
}
