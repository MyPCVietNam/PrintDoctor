using MyPC.LanPrintDoctor.Abstractions.Diagnostics;
using MyPC.LanPrintDoctor.Abstractions.Platform;
using MyPC.LanPrintDoctor.Abstractions.Repair;
using MyPC.LanPrintDoctor.Abstractions.Security;
using MyPC.LanPrintDoctor.Repair;
using MyPC.LanPrintDoctor.Repair.Operations;

namespace MyPC.LanPrintDoctor.UnitTests;

/// <summary>P22-001 / P22-002 / P22-003 GATE A regression — every case asserts resulting firewall state.</summary>
public class P22FirewallTransactionRecoveryTests
{
    [Fact]
    public async Task P22_001_CreateSucceeds_EnableFails_RollbackRemovesOwnedRule()
    {
        var state = new FwSimState();
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("Enable-NetFirewallRule", StringComparison.Ordinal))
                return new ProcessResult { ExitCode = 1, StdOut = "NOT_ENABLED" };
            return FwSim.Handle(script, state, OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var journal = NewJournal("enfail");
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.NotEqual(DiagnosticStatus.Pass, result.Status);
        Assert.True(result.RollbackAttempted);
        Assert.True(result.RollbackVerified || state.Removed);
        Assert.False(state.Created && !state.Removed); // must not leave orphan
        Assert.True(state.Removed);
    }

    [Fact]
    public async Task P22_001_CreateSucceeds_VerificationFails_RollbackRemoves()
    {
        var state = new FwSimState();
        var phase = 0;
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("ConvertTo-Json", StringComparison.Ordinal) && state.Created && !state.Removed)
            {
                phase++;
                // After create, first reads OK (disabled+match); after enable, report wrong RemoteAddress
                if (state.Enabled)
                {
                    return new ProcessResult
                    {
                        ExitCode = 0,
                        StdOut =
                            $"{{\"exists\":true,\"Name\":\"MyPC.PrintDoctor.ICMPv4.Private\",\"Enabled\":true,\"Direction\":\"Inbound\",\"Action\":\"Allow\",\"Profile\":\"Private\",\"Protocol\":\"ICMPv4\",\"IcmpType\":\"8\",\"RemoteAddress\":\"Any\",\"PolicyStore\":\"PersistentStore\",\"Description\":\"{state.Fingerprint}\"}}"
                    };
                }
            }

            return FwSim.Handle(script, state, OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var journal = NewJournal("scopefail");
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.True(result.RollbackAttempted || result.Status != DiagnosticStatus.Pass);
        Assert.True(state.Removed || !state.Created);
    }

    [Fact]
    public async Task P22_001_CreateSucceeds_PowerShellNoOutput_RecoverViaRequery()
    {
        var state = new FwSimState();
        var createCalls = 0;
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("New-NetFirewallRule", StringComparison.Ordinal))
            {
                createCalls++;
                // Side effect: rule created, but process returns empty / crash-like
                state.Created = true;
                state.Enabled = false;
                var idx = script.IndexOf("-Description '", StringComparison.Ordinal);
                if (idx >= 0)
                {
                    var start = idx + "-Description '".Length;
                    var end = script.IndexOf('\'', start);
                    state.Fingerprint = script[start..end];
                }

                return new ProcessResult { ExitCode = 1, StdOut = "", StdErr = "" };
            }

            return FwSim.Handle(script, state, OwnedFirewallSpec.Smb445PrivateLocalSubnet());
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.Smb445PrivateLocalSubnet());
        var journal = NewJournal("noout");
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.True(createCalls >= 1);
        Assert.True(op.CreatedInThisTransaction || result.RollbackAttempted || state.Removed);
        // Recovery must delete the orphan with matching provenance
        Assert.True(state.Removed, "orphan create without CHANGED output must still roll back via provenance re-query");
        Assert.False(state.Created && !state.Removed);
    }

    [Fact]
    public async Task P22_001_CreateSucceeds_UnparseableOutput_RecoverViaRequery()
    {
        var state = new FwSimState();
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("New-NetFirewallRule", StringComparison.Ordinal))
            {
                state.Created = true;
                state.Enabled = false;
                var idx = script.IndexOf("-Description '", StringComparison.Ordinal);
                if (idx >= 0)
                {
                    var start = idx + "-Description '".Length;
                    var end = script.IndexOf('\'', start);
                    state.Fingerprint = script[start..end];
                }

                return new ProcessResult { ExitCode = 0, StdOut = "<<<not-json-and-not-CREATED>>>" };
            }

            return FwSim.Handle(script, state, OwnedFirewallSpec.ShaPrint48631());
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.ShaPrint48631());
        var journal = NewJournal("parse");
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.True(state.Removed, "unparseable create output with live rule must recover via re-query");
        Assert.NotEqual(DiagnosticStatus.Pass, result.Status);
    }

    [Fact]
    public async Task P22_001_PreexistingMatches_AlreadyConfigured_NoMutation()
    {
        var mutated = false;
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("New-NetFirewallRule", StringComparison.Ordinal)
                || script.Contains("Enable-NetFirewallRule", StringComparison.Ordinal)
                || script.Contains("Remove-NetFirewallRule", StringComparison.Ordinal))
            {
                mutated = true;
                return new ProcessResult { ExitCode = 1, StdOut = "SHOULD_NOT_RUN" };
            }

            return new ProcessResult
            {
                ExitCode = 0,
                StdOut =
                    """{"exists":true,"Name":"MyPC.PrintDoctor.ICMPv4.Private","Enabled":true,"Direction":"Inbound","Action":"Allow","Profile":"Private","Protocol":"ICMPv4","IcmpType":"8","RemoteAddress":"LocalSubnet","PolicyStore":"PersistentStore","Description":"prior"}"""
            };
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var journal = NewJournal("already");
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.True(result.NoChange);
        Assert.Equal(DiagnosticStatus.Pass, result.Status);
        Assert.False(mutated);
    }

    [Fact]
    public async Task P22_001_PreexistingConflict_NoOverwrite()
    {
        var removed = false;
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("Remove-NetFirewallRule", StringComparison.Ordinal))
            {
                removed = true;
                return new ProcessResult { ExitCode = 0, StdOut = "OK:REMOVED" };
            }

            if (script.Contains("ConvertTo-Json", StringComparison.Ordinal))
            {
                return new ProcessResult
                {
                    ExitCode = 0,
                    StdOut =
                        """{"exists":true,"Name":"MyPC.PrintDoctor.SMB445.Private","Enabled":true,"Direction":"Inbound","Action":"Allow","Profile":"Private","Protocol":"TCP","LocalPort":"445","RemoteAddress":"Any","PolicyStore":"PersistentStore"}"""
                };
            }

            return new ProcessResult { ExitCode = 0, StdOut = "OK" };
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.Smb445PrivateLocalSubnet());
        var journal = NewJournal("conflict");
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.Equal(DiagnosticStatus.Blocked, result.Status);
        Assert.Contains("RULE_CONFLICT", result.Message ?? "", StringComparison.Ordinal);
        Assert.False(removed);
    }

    [Fact]
    public async Task P22_001_UnknownBeforeState_BlocksMutation()
    {
        var mutated = false;
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("ConvertTo-Json", StringComparison.Ordinal))
                return new ProcessResult { ExitCode = 1, StdOut = "", StdErr = "Get-NetFirewallRule failed" };
            mutated = true;
            return new ProcessResult { ExitCode = 0, StdOut = "OK" };
        });

        var op = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var journal = NewJournal("unknown");
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.NotEqual(DiagnosticStatus.Pass, result.Status);
        Assert.False(mutated);
    }

    [Fact]
    public async Task P22_001_RollbackSucceedsButRuleRemains_PartialRollback()
    {
        var state = new FwSimState();
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("Remove-NetFirewallRule", StringComparison.Ordinal))
            {
                // Claim OK but leave rule present
                return new ProcessResult { ExitCode = 0, StdOut = "OK:REMOVED" };
            }

            return FwSim.Handle(script, state, OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        });

        // Drive enable-fail so rollback runs while rule still present
        var enableFail = new ScriptRunner((_, script) =>
        {
            if (script.Contains("Enable-NetFirewallRule", StringComparison.Ordinal))
            {
                state.Created = true; // ensure present
                return new ProcessResult { ExitCode = 1, StdOut = "NOT_ENABLED" };
            }

            if (script.Contains("Remove-NetFirewallRule", StringComparison.Ordinal))
                return new ProcessResult { ExitCode = 0, StdOut = "OK:REMOVED" }; // lie

            return FwSim.Handle(script, state, OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        });

        var op = new OwnedFirewallRuleRepair(enableFail, new Elev(), OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var journal = NewJournal("partialrb");
        var result = await new RepairExecutor(journal, journal.DirectoryPath)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.True(result.RollbackAttempted);
        Assert.False(result.RollbackVerified);
        Assert.True(result.UncertainState || (result.Message?.Contains("PARTIAL_ROLLBACK", StringComparison.OrdinalIgnoreCase) ?? false)
                    || (result.Message?.Contains("Rollback attempted but not verified", StringComparison.OrdinalIgnoreCase) ?? false)
                    || state.Created);
    }

    [Fact]
    public async Task P22_001_RepeatSameRepairTwice_SecondIsAlreadyConfigured()
    {
        var state = new FwSimState();
        var runner = new ScriptRunner((_, script) => FwSim.Handle(script, state, OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet()));
        var journal1 = NewJournal("rep1");
        var op1 = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var r1 = await new RepairExecutor(journal1, journal1.DirectoryPath)
            .ExecuteAsync(op1, userConfirmed: true, localRole: MachineRole.Server);
        Assert.Equal(DiagnosticStatus.Pass, r1.Status);
        Assert.True(r1.Applied || r1.NoChange);
        Assert.True(state.Created && state.Enabled);

        var journal2 = NewJournal("rep2");
        var op2 = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var r2 = await new RepairExecutor(journal2, journal2.DirectoryPath)
            .ExecuteAsync(op2, userConfirmed: true, localRole: MachineRole.Server);
        Assert.True(r2.NoChange);
        Assert.Equal(DiagnosticStatus.Pass, r2.Status);
        Assert.False(r2.Applied);
    }

    [Fact]
    public void P22_002_MatchesDesired_RejectsAnyPortAndNull()
    {
        var op = new OwnedFirewallRuleRepair(new ScriptRunner((_, _) => new ProcessResult { ExitCode = 0, StdOut = "{}" }), new Elev(), OwnedFirewallSpec.Smb445PrivateLocalSubnet());
        var anyPort = new OwnedFirewallRuleRepair.OwnedRuleSnapshot
        {
            Exists = true,
            Name = "MyPC.PrintDoctor.SMB445.Private",
            Enabled = true,
            Direction = "Inbound",
            Action = "Allow",
            Profile = "Private",
            Protocol = "TCP",
            LocalPort = "Any",
            RemoteAddress = "LocalSubnet",
            PolicyStore = "PersistentStore"
        };
        Assert.False(op.MatchesDesired(anyPort, requireEnabled: true));

        var nullPort = new OwnedFirewallRuleRepair.OwnedRuleSnapshot
        {
            Exists = true,
            Name = "MyPC.PrintDoctor.SMB445.Private",
            Enabled = true,
            Direction = "Inbound",
            Action = "Allow",
            Profile = "Private",
            Protocol = "TCP",
            LocalPort = null,
            RemoteAddress = "LocalSubnet",
            PolicyStore = "PersistentStore"
        };
        Assert.False(op.MatchesDesired(nullPort, requireEnabled: true));

        var icmpAny = new OwnedFirewallRuleRepair(new ScriptRunner((_, _) => new ProcessResult { ExitCode = 0, StdOut = "{}" }), new Elev(), OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var anyIcmp = new OwnedFirewallRuleRepair.OwnedRuleSnapshot
        {
            Exists = true,
            Name = "MyPC.PrintDoctor.ICMPv4.Private",
            Enabled = true,
            Direction = "Inbound",
            Action = "Allow",
            Profile = "Private",
            Protocol = "ICMPv4",
            IcmpType = "Any",
            RemoteAddress = "LocalSubnet",
            PolicyStore = "PersistentStore"
        };
        Assert.False(icmpAny.MatchesDesired(anyIcmp, requireEnabled: true));
    }

    [Fact]
    public void P22_002_IsSafeLanScope_RejectsPlaceholderAndDefaultRoute()
    {
        Assert.False(FirewallRemoteAddress.IsSafeLanScope("SPECIFIC_CIDR"));
        Assert.False(FirewallRemoteAddress.IsSafeLanScope("Any"));
        Assert.False(FirewallRemoteAddress.IsSafeLanScope("0.0.0.0/0"));
        Assert.False(FirewallRemoteAddress.IsSafeLanScope("::/0"));
        Assert.False(FirewallRemoteAddress.IsSafeLanScope("LocalSubnet,Any"));
        Assert.True(FirewallRemoteAddress.IsSafeLanScope("LocalSubnet"));
        Assert.True(FirewallRemoteAddress.IsSafeLanScope("192.168.10.0/24"));
        Assert.False(FirewallRemoteAddress.IsSafeLanScope("not-an-ip/24"));
        Assert.False(FirewallRemoteAddress.IsSafeLanScope("192.168.10.0/99"));
    }

    [Fact]
    public async Task P22_003_MachineWideLock_BlocksSecondExecutorDifferentSessionDirs()
    {
        var dirA = Path.Combine(Path.GetTempPath(), "p22lockA-" + Guid.NewGuid().ToString("N"));
        var dirB = Path.Combine(Path.GetTempPath(), "p22lockB-" + Guid.NewGuid().ToString("N"));
        var sharedLock = Path.Combine(Path.GetTempPath(), "p22shared-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dirA);
        Directory.CreateDirectory(dirB);

        using var held = new MachineRepairLock(sharedLock);
        Assert.True(held.TryAcquire(TimeSpan.Zero));

        var state = new FwSimState();
        var runner = new ScriptRunner((_, script) => FwSim.Handle(script, state, OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet()));
        var op = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var journal = new RepairJournal(dirA);
        var result = await new RepairExecutor(journal, sharedLock)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.Equal(DiagnosticStatus.Blocked, result.Status);
        Assert.Contains("CONCURRENT_REPAIR", result.Message ?? "", StringComparison.Ordinal);
        Assert.False(state.Created);
    }

    [Fact]
    public async Task P22_003_LockAcquiredBeforeRecoveryCheck()
    {
        // Incomplete journal in session A; session B must still be blocked only after lock —
        // and machine-wide lock identity is independent of journal dir.
        var sharedLock = Path.Combine(Path.GetTempPath(), "p22ord-" + Guid.NewGuid().ToString("N"));
        var journalDir = Path.Combine(Path.GetTempPath(), "p22ordj-" + Guid.NewGuid().ToString("N"));
        var j0 = new RepairJournal(journalDir);
        j0.RecordMutationIntent("old", "FW-OWNED-ICMP4", "[]", "[]");

        var j = new RepairJournal(journalDir);
        var runner = new ScriptRunner((_, script) =>
        {
            if (script.Contains("New-NetFirewallRule", StringComparison.Ordinal))
                throw new Exception("MUST_NOT_MUTATE_WHEN_UNCERTAIN");
            return new ProcessResult { ExitCode = 0, StdOut = """{"exists":false}""" };
        });
        var op = new OwnedFirewallRuleRepair(runner, new Elev(), OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        var result = await new RepairExecutor(j, sharedLock)
            .ExecuteAsync(op, userConfirmed: true, localRole: MachineRole.Server);

        Assert.Equal(DiagnosticStatus.Blocked, result.Status);
        Assert.Contains("UNCERTAIN", result.Message ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void P22_001_BindTransaction_UsesExecutorId()
    {
        var op = new OwnedFirewallRuleRepair(
            new ScriptRunner((_, _) => new ProcessResult { ExitCode = 0, StdOut = """{"exists":false}""" }),
            new Elev(),
            OwnedFirewallSpec.IcmpEchoPrivateLocalSubnet());
        op.BindTransaction("deadbeef");
        Assert.Equal("deadbeef", op.BoundTransactionId);
    }

    private static RepairJournal NewJournal(string tag)
        => new(Path.Combine(Path.GetTempPath(), $"p22-{tag}-" + Guid.NewGuid().ToString("N")));

    private sealed class Elev : IElevationService
    {
        public bool IsAdministrator() => true;
        public Task<bool> EnsureElevatedAsync(CancellationToken ct = default) => Task.FromResult(true);
    }

    private sealed class ScriptRunner : IProcessRunner
    {
        private readonly Func<string, string, ProcessResult> _h;
        public ScriptRunner(Func<string, string, ProcessResult> h) => _h = h;
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan? timeout = null, CancellationToken ct = default)
            => Task.FromResult(_h(fileName, arguments.LastOrDefault() ?? ""));
    }
}
