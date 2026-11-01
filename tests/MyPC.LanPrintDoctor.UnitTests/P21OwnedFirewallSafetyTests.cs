using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;

namespace MyPC.LanPrintDoctor.UnitTests;

public class P21OwnedFirewallSafetyTests
{
    [Fact]
    public async Task P21_001_PreexistingRule_RuleExists_DoesNotDelete()
    {
        var scripts = new List<string>();
        var runner = new ScriptRunner((file, script) =>
        {
            scripts.Add(script);
            if (script.Contains("exists", StringComparison.OrdinalIgnoreCase)
                && script.Contains("Get-NetFirewallRule", StringComparison.Ordinal)
                && script.Contains("ConvertTo-Json", StringComparison.Ordinal))
            {
                // Backup / read: preexisting valid-ish rule
                return new ProcessResult
                {
                    ExitCode = 0,
                    StdOut = """{"exists":true,"Name":"MyPC.PrintDoctor.ICMPv4.Private","Enabled":true,"Direction":"Inbound","Action":"Allow","Profile":"Private","Protocol":"ICMPv4","LocalPort":null,"IcmpType":"8","RemoteAddress":"LocalSubnet","PolicyStore":"PersistentStore","Description":"prior-tx"}"""
                };
            }
            if (script.Contains("Remove-NetFirewallRule", StringComparison.Ordinal))
                return new ProcessResult { ExitCode = 0, StdOut = "OK:REMOVED" };
            if (script.Contains("New-NetFirewallRule", StringComparison.Ordinal))
                return new ProcessResult { ExitCode = 1, StdOut = "RULE_EXISTS:MyPC.PrintDoctor.ICMPv4.Private" };
            return new ProcessResult { ExitCode = 0, StdOut = "{}" };
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev { Admin = true }, OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var journal = new RepairJournal(Path.Combine(Path.GetTempPath(), "p21-" + Guid.NewGuid().ToString("N")));
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.Equal(DiagnosticStatus.Pass, result.Status); // ALREADY_CONFIGURED / NoChange when match
        Assert.True(result.NoChange || result.Status == DiagnosticStatus.Blocked || result.Status == DiagnosticStatus.Pass);
        Assert.DoesNotContain(scripts, s => s.Contains("Remove-NetFirewallRule", StringComparison.Ordinal));
    }

    [Fact]
    public async Task P21_001_PreexistingMismatch_Blocked_NoDelete()
    {
        var removed = false;
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("ConvertTo-Json", StringComparison.Ordinal) && script.Contains("exists", StringComparison.OrdinalIgnoreCase))
            {
                return new ProcessResult
                {
                    ExitCode = 0,
                    StdOut = """{"exists":true,"Name":"MyPC.PrintDoctor.ICMPv4.Private","Enabled":true,"Direction":"Inbound","Action":"Allow","Profile":"Public,Private","Protocol":"ICMPv4","IcmpType":"8","RemoteAddress":"Any","PolicyStore":"PersistentStore"}"""
                };
            }
            if (script.Contains("Remove-NetFirewallRule", StringComparison.Ordinal))
            {
                removed = true;
                return new ProcessResult { ExitCode = 0, StdOut = "OK:REMOVED" };
            }
            return new ProcessResult { ExitCode = 0, StdOut = "OK" };
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev { Admin = true }, OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var journal = new RepairJournal(Path.Combine(Path.GetTempPath(), "p21m-" + Guid.NewGuid().ToString("N")));
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.Equal(DiagnosticStatus.Blocked, result.Status);
        Assert.Contains("RULE_EXISTS_MISMATCH", result.Message ?? "", StringComparison.Ordinal);
        Assert.False(removed);
        Assert.False(result.RollbackAttempted); // Rollback may be called but Attempted=false for no-create
    }

    [Fact]
    public async Task P21_001_CreateThenRollback_OnlyDeletesWhenCreated()
    {
        var created = false;
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("ConvertTo-Json", StringComparison.Ordinal) && script.Contains("exists", StringComparison.OrdinalIgnoreCase))
            {
                return new ProcessResult
                {
                    ExitCode = 0,
                    StdOut = created
                        ? """{"exists":true,"Name":"MyPC.PrintDoctor.SMB445.Private","Enabled":true,"Direction":"Inbound","Action":"Allow","Profile":"Private","Protocol":"TCP","LocalPort":"445","RemoteAddress":"LocalSubnet","PolicyStore":"PersistentStore","Description":"tx:"}"""
                        : """{"exists":false}"""
                };
            }
            if (script.Contains("New-NetFirewallRule", StringComparison.Ordinal))
            {
                created = true;
                return new ProcessResult { ExitCode = 0, StdOut = "CHANGED:MyPC.PrintDoctor.SMB445.Private|FINGERPRINT:tx:abc" };
            }
            if (script.Contains("Remove-NetFirewallRule", StringComparison.Ordinal))
            {
                Assert.Contains("PROVENANCE", script, StringComparison.Ordinal);
                return new ProcessResult { ExitCode = 0, StdOut = "OK:REMOVED" };
            }
            return new ProcessResult { ExitCode = 0, StdOut = "PASS" };
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev { Admin = true }, OwnedFirewallSpec.Smb445PrivateLocalSubnet());
        await op.BackupAsync();
        await op.ApplyAsync();
        Assert.True(op.CreatedInThisTransaction);
        // Force verify fail path via direct rollback
        var rb = await op.RollbackAsync(new RepairBackup
        {
            BackupId = "b",
            Path = "j",
            CreatedAt = DateTimeOffset.UtcNow,
            PayloadJson = """{"exists":false}"""
        });
        Assert.True(rb.Attempted);
    }

    [Fact]
    public async Task P21_001_ApplyFailBeforeCreate_RollbackDoesNotRemove()
    {
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("{\"exists\"", StringComparison.Ordinal) || script.Contains("'exists'", StringComparison.Ordinal) ||
                (script.Contains("exists", StringComparison.OrdinalIgnoreCase) && script.Contains("ConvertTo-Json", StringComparison.Ordinal)))
                return new ProcessResult { ExitCode = 0, StdOut = """{"exists":false}""" };
            if (script.Contains("New-NetFirewallRule", StringComparison.Ordinal))
                return new ProcessResult { ExitCode = 1, StdOut = "", StdErr = "ACCESS_DENIED" };
            if (script.Contains("Remove-NetFirewallRule", StringComparison.Ordinal))
                throw new Exception("MUST_NOT_REMOVE");
            return new ProcessResult { ExitCode = 0, StdOut = "OK" };
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev { Admin = true }, OwnedFirewallSpec.ShaPrint48631());
        var journal = new RepairJournal(Path.Combine(Path.GetTempPath(), "p21f-" + Guid.NewGuid().ToString("N")));
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);
        Assert.False(result.Status == DiagnosticStatus.Pass && result.Applied);
        Assert.False(op.CreatedInThisTransaction);
    }

    [Fact]
    public void P21_002_ExactRemote_RejectsCompoundAny()
    {
        Assert.False(FirewallRemoteAddress.ExactMatch("LocalSubnet,Any", "LocalSubnet"));
        Assert.False(FirewallRemoteAddress.ProfileIsPrivateOnly("Private,Public"));
        Assert.True(FirewallRemoteAddress.ProfileIsPrivateOnly("Private"));
    }

    private sealed class Elev : IElevationService
    {
        public bool Admin { get; init; }
        public bool IsAdministrator() => Admin;
        public Task<bool> EnsureElevatedAsync(CancellationToken ct = default) => Task.FromResult(Admin);
    }

    private sealed class ScriptRunner : IProcessRunner
    {
        private readonly Func<string, string, ProcessResult> _h;
        public ScriptRunner(Func<string, string, ProcessResult> h) => _h = h;
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan? timeout = null, CancellationToken ct = default)
            => Task.FromResult(_h(fileName, arguments.LastOrDefault() ?? ""));
    }
}
